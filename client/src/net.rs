//! RPC helpers.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;
use bierpc::error::RpcError;
use bierpc::rpc::{ClientConfig, ClientStream, RpcClient, Target};
use bierpc::serialize::Deserialize;
use protocol::{auth, tls};
use protocol::{
    Action, ApiError, AuthFailure, ConsoleLine, DirEntry, InstanceStatResponse, InstanceStatus,
    Reply, Request, Response, Session, SessionStart,
};
use tokio::io::BufStream;

pub const RPC_TIMEOUT: Duration = Duration::from_secs(5);

/// The live, mutually-authenticated stream a side-channel session runs over —
/// bierpc's persistent connection, reused for the call's reply afterwards.
pub type SessionStream = BufStream<ClientStream>;

fn client_config(key: &[u8]) -> ClientConfig {
    ClientConfig {
        connect_timeout: RPC_TIMEOUT,
        call_timeout: Some(RPC_TIMEOUT),
        // Console tails and large directory listings outgrow the 1 MiB default.
        max_message_bytes: 8 * 1024 * 1024,
        // Mutual TLS pinned to the identity derived from this key: a server
        // with a different key cannot complete the handshake, and the same
        // cert authenticates us on the (HMAC-less) persistent path.
        tls: Some(tls::Identity::derive(key).client_config().expect("building the client TLS identity")),
        ..Default::default()
    }
}

/// Tell "nothing is listening" apart from "the handshake was rejected". A TLS
/// pin mismatch is a key problem, not an unreachable host, and deserves the
/// keygen hint rather than "is the server running?".
fn connect_error(addr: Target, e: RpcError) -> NetError {
    let refused = matches!(&e, RpcError::IoError { err } if matches!(
        err.kind(),
        std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::HostUnreachable
            | std::io::ErrorKind::NetworkUnreachable
            | std::io::ErrorKind::AddrNotAvailable
    ));
    if refused || matches!(e, RpcError::TimedOut { .. }) {
        NetError::Unreachable(format!("cannot connect to {addr} ({}) — is the server running?", rpc_detail(&e)))
    } else {
        // A completed TCP connection that then failed the TLS handshake is a
        // key mismatch (or a MITM without the key); same remedy as a rejected key.
        NetError::Auth(AuthFailure::BadKey)
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
pub async fn call_with_key(addr: Target, key: &[u8], action: Action) -> Result<Response, NetError> {
    if key.len() != auth::KEY_LEN {
        return Err(NetError::NoKey);
    }

    let payload = auth::encode(&action).await
        .map_err(|e| NetError::Protocol(format!("could not encode the request: {e}")))?;
    let request = auth::sign_request(key, payload);
    let nonce = request.nonce.clone();

    let mut client = RpcClient::<Request>::new_with_config(addr.to_socket_addr(), client_config(key)).await
        .map_err(|e| connect_error(addr, e))?;

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
    pub addr: Target,
    pub key: Vec<u8>,
}

impl Endpoint {
    pub fn new(addr: Target, key: Vec<u8>) -> Self {
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

/// Run a side-channel `session` over a fresh mutually-authenticated
/// connection. The server validates first (sending `SessionStart`); on success
/// `body` gets that and the live stream to speak the session protocol over.
pub async fn session<F>(endpoint: &Endpoint, action: Session, body: F) -> anyhow::Result<()>
where
    F: AsyncFnOnce(SessionStart, &mut SessionStream) -> anyhow::Result<()>,
{
    let addr = endpoint.addr;
    let mut client = RpcClient::<Request, Session>::new_with_config(addr.to_socket_addr(), client_config(&endpoint.key)).await
        .map_err(|e| anyhow::anyhow!("{}", connect_error(addr, e)))?;

    // The body's own error (as opposed to a transport error) is captured here
    // so its context survives, rather than collapsing to a generic RpcError.
    let mut body_err: Option<anyhow::Error> = None;
    let outcome = client.call_persistent::<Response, _>(action, async |stream| {
        let start = Result::<SessionStart, ApiError>::deserialize(&mut *stream).await
            .map_err(RpcError::from)?;
        // On rejection, leave the stream untouched — the reply carries the same
        // error and is read next.
        if let Ok(info) = start
            && let Err(e) = body(info, stream).await {
            body_err = Some(e);
            return Err(RpcError::IoError { err: std::io::Error::other("session body failed") });
        }
        Ok(())
    }).await;

    if let Some(e) = body_err {
        return Err(e);
    }
    match outcome {
        Ok(Response::Done) => Ok(()),
        Ok(Response::Error(e)) => Err(anyhow::anyhow!("{e}")),
        Ok(other) => anyhow::bail!("unexpected session reply: {other:?}"),
        Err(e) => Err(anyhow::anyhow!("session failed: {}", rpc_detail(&e))),
    }
}
