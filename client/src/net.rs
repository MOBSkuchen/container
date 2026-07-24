//! RPC helpers.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;
use anyhow::Context;
use bierpc::error::RpcError;
use bierpc::rpc::{ClientConfig, RpcClient};
use protocol::auth;
use protocol::{
    Action, ApiError, AuthFailure, ConsoleLine, DirEntry, InstanceStatResponse, InstanceStatus,
    Reply, Request, Response,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub const RPC_TIMEOUT: Duration = Duration::from_secs(5);

fn client_config() -> ClientConfig {
    ClientConfig {
        connect_timeout: RPC_TIMEOUT,
        call_timeout: Some(RPC_TIMEOUT),
        // Console tails and large directory listings outgrow the 1 MiB default.
        max_message_bytes: 8 * 1024 * 1024,
        ..Default::default()
    }
}

/// `RpcError` has no Display; pick out the part worth showing.
fn rpc_detail(e: &RpcError) -> String {
    match e {
        RpcError::IoError { err } => err.to_string(),
        RpcError::TimedOut { phase, after } => format!("{phase} timed out after {}s", after.as_secs()),
        RpcError::CallTypeRejected { reason } => reason.clone(),
        RpcError::ConnectionPoisoned => "connection is poisoned".to_string(),
    }
}

#[derive(Debug, Clone)]
pub enum NetError {
    /// Could not get a connection at all
    Unreachable(String),
    /// Connected, but the exchange did not complete or made no sense
    Protocol(String),
    /// The key was refused, or the reply could not be authenticated
    Auth(AuthFailure),
    /// No key configured for this server yet
    NoKey,
    /// The server refused
    Api(ApiError),
}

impl std::fmt::Display for NetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetError::Unreachable(m) | NetError::Protocol(m) => f.write_str(m),
            NetError::Auth(failure) => write!(f, "{failure}"),
            NetError::NoKey => f.write_str(
                "no authentication key for this server — run `client keygen <phrase>` \
                 with the phrase the server was given",
            ),
            NetError::Api(e) => write!(f, "{e}"),
        }
    }
}

impl NetError {
    /// Short form for the landing page, where there is no room for detail.
    pub fn short(&self) -> &'static str {
        match self {
            NetError::Unreachable(_) => "unreachable",
            NetError::Protocol(_) => "protocol error",
            // These two are the first thing a new user hits, and the row has
            // room, so they name the fix rather than just the symptom.
            NetError::Auth(_) => "key rejected — run `client keygen <phrase>`",
            NetError::NoKey => "no key — run `client keygen <phrase>`",
            NetError::Api(_) => "refused",
        }
    }
}

/// One authenticated round trip: sign the action, dial, verify the reply.
pub async fn call_with_key(addr: SocketAddr, key: &[u8], action: Action) -> Result<Response, NetError> {
    if key.len() != auth::KEY_LEN {
        return Err(NetError::NoKey);
    }

    let payload = auth::encode(&action).await
        .map_err(|e| NetError::Protocol(format!("could not encode the request: {e}")))?;
    let request = auth::sign_request(key, payload);
    let nonce = request.nonce.clone();

    let mut client = RpcClient::<Request>::new_with_config(addr, client_config()).await
        .map_err(|e| NetError::Unreachable(format!(
            "cannot connect to {addr} ({}) — is the server running?", rpc_detail(&e))))?;

    let reply = client.call::<Reply>(request).await
        .map_err(|e| NetError::Protocol(format!(
            "{addr} accepted the connection but the request failed: {}", rpc_detail(&e))))?;

    let payload = auth::verify_reply(key, &nonce, &reply).map_err(NetError::Auth)?;
    match auth::decode::<Response>(payload).await {
        Err(e) => Err(NetError::Protocol(format!("could not decode the reply: {e}"))),
        Ok(Response::Error(e)) => Err(NetError::Api(e)),
        Ok(resp) => Ok(resp),
    }
}

/// A server plus the key to reach it with. Carried together so no call site
/// can accidentally talk to one server with another's key.
#[derive(Clone, Debug)]
pub struct Endpoint {
    pub addr: SocketAddr,
    pub key: Vec<u8>,
}

impl Endpoint {
    pub fn new(addr: SocketAddr, key: Vec<u8>) -> Self {
        Self { addr, key }
    }
}

pub async fn call(endpoint: &Endpoint, action: Action) -> Result<Response, NetError> {
    call_with_key(endpoint.addr, &endpoint.key, action).await
}

fn unexpected(what: &str, got: Response) -> NetError {
    NetError::Protocol(format!("expected {what}, got {got:?}"))
}

/// Raw counters
#[derive(Debug, Clone)]
pub struct Vitals {
    pub total_stg: u64,
    pub free_stg: u64,
    pub total_ram: u64,
    pub free_ram: u64,
    pub network_recv: u64,
    pub network_trans: u64,
    pub cpu_usage: f64,
    pub instances: Vec<InstanceStatResponse>,
    /// The server would honor `Bootstrap` right now.
    pub bootstrap: bool,
}

pub async fn stat(endpoint: &Endpoint) -> Result<Vitals, NetError> {
    match call(endpoint, Action::Stat).await? {
        Response::StatResponse {
            total_stg, free_stg, total_ram, free_ram,
            network_recv, network_trans, cpu_usage, instances, bootstrap,
        } => Ok(Vitals {
            total_stg, free_stg, total_ram, free_ram,
            network_recv, network_trans, cpu_usage,
            instances: sorted_by_name(instances),
            bootstrap,
        }),
        other => Err(unexpected("StatResponse", other)),
    }
}

fn sorted_by_name(instances: HashMap<u128, InstanceStatResponse>) -> Vec<InstanceStatResponse> {
    let mut list: Vec<_> = instances.into_values().collect();
    list.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    list
}

/// Ancient artifact
pub async fn ping(endpoint: &Endpoint) -> Result<(), NetError> {
    match call(endpoint, Action::Ping).await? {
        Response::Pong => Ok(()),
        other => Err(unexpected("Pong", other)),
    }
}

pub async fn check(endpoint: &Endpoint, id: u128) -> Result<InstanceStatus, NetError> {
    match call(endpoint, Action::CheckInstance { id }).await? {
        Response::InstanceStatus(st) => Ok(st),
        other => Err(unexpected("InstanceStatus", other)),
    }
}

/// Recent console output for an instance, oldest first
pub async fn tail_console(endpoint: &Endpoint, id: u128, lines: u32) -> Result<(Vec<ConsoleLine>, u64), NetError> {
    match call(endpoint, Action::TailConsole { id, lines }).await? {
        Response::Console { lines, dropped } => Ok((lines, dropped)),
        other => Err(unexpected("Console", other)),
    }
}

pub async fn create(endpoint: &Endpoint, spec: crate::instance_form::Parsed) -> Result<u128, NetError> {
    let action = Action::CreateInstance {
        name: spec.name,
        source: spec.source.to_source(),
        command: spec.command,
        args: spec.args,
        env: spec.env,
        autostart: spec.autostart,
        retry_policy: spec.retry_policy,
    };
    match call(endpoint, action).await? {
        Response::InstanceCreated { id } => Ok(id),
        other => Err(unexpected("InstanceCreated", other)),
    }
}

/// For actions whose only interesting outcome is success or failure
pub async fn done(endpoint: &Endpoint, action: Action) -> Result<(), NetError> {
    match call(endpoint, action).await? {
        Response::Done => Ok(()),
        other => Err(unexpected("Done", other)),
    }
}

/// Resolved path plus its entries, as the server listed them
pub async fn list_dir(endpoint: &Endpoint, path: PathBuf) -> Result<(PathBuf, Vec<DirEntry>), NetError> {
    match call(endpoint, Action::ListDir { path }).await? {
        Response::DirListing { path, entries } => Ok((path, entries)),
        other => Err(unexpected("DirListing", other)),
    }
}

/// Ask for a side-channel session and complete its token handshake.
/// The stream is ready for the session protocol when this returns.
pub async fn open_session(endpoint: &Endpoint, action: Action) -> anyhow::Result<TcpStream> {
    let addr = endpoint.addr;
    let (port, token, ttl_secs) = match call(endpoint, action).await {
        Ok(Response::SessionOpened { port, token, ttl_secs, .. }) => (port, token, ttl_secs),
        Ok(other) => anyhow::bail!("expected a session offer, got {other:?}"),
        Err(e) => anyhow::bail!("{e}"),
    };

    let mut stream = tokio::time::timeout(
        Duration::from_secs(ttl_secs.max(1)),
        TcpStream::connect((addr.ip(), port)),
    ).await
        .with_context(|| format!("session port {port} did not accept a connection within {ttl_secs}s"))?
        .with_context(|| format!("connecting to session port {port}"))?;

    // Nagle would batch a keystroke and its echo into visible typing lag.
    let _ = stream.set_nodelay(true);

    stream.write_all(&token).await.context("sending the session token")?;
    let mut ack = [0u8; 1];
    stream.read_exact(&mut ack).await.context("the server closed the session without acknowledging it")?;
    if ack[0] != 1 {
        anyhow::bail!("the server rejected the session token");
    }
    Ok(stream)
}
