//! Resolving a command-line instance reference to a concrete server+instance.
//!
//! Accepted forms:
//!   `server/instance`  — unambiguous, and what the manage screen suggests
//!   `instance`         — searched across every known server; ambiguity is an
//!                        error rather than a silent pick
//!   ids work anywhere a name does (32-hex, as printed by the server)

use anyhow::{Context, bail};
use protocol::{Action, InstanceStatResponse, Response};

use crate::book::{Book, ServerEntry};
use crate::net::{self, Endpoint};

pub struct Resolved {
    pub server: ServerEntry,
    pub instance: InstanceStatResponse,
    pub endpoint: Endpoint,
}

impl Resolved {
    /// The canonical `server/instance` spelling, for messages.
    pub fn label(&self) -> String {
        format!("{}/{}", self.server.name, self.instance.name)
    }
}

pub async fn resolve(book: &Book, spec: &str) -> anyhow::Result<Resolved> {
    if book.servers.is_empty() {
        bail!("no servers configured — add one in the TUI first (run `client` with no arguments)");
    }

    match spec.split_once('/') {
        Some((server_spec, instance_spec)) => {
            let server = book.find_by_name(server_spec)
                .with_context(|| {
                    let known = book.servers.iter().map(|s| s.name.as_str()).collect::<Vec<_>>().join(", ");
                    format!("no server named '{server_spec}' (known: {known})")
                })?
                .clone();
            let endpoint = book.endpoint_or_keyless(&server);
            let instances = list(&endpoint).await?;
            let instance = pick(&instances, instance_spec)
                .with_context(|| format!("server '{}' has no instance '{instance_spec}'", server.name))?;
            Ok(Resolved { server, instance, endpoint })
        }
        None => resolve_bare(book, spec).await,
    }
}

/// Search every server. Unreachable ones are skipped rather than fatal — one
/// server being down should not stop you attaching to another.
async fn resolve_bare(book: &Book, spec: &str) -> anyhow::Result<Resolved> {
    let mut hits = Vec::new();
    let mut failures = Vec::new();

    for server in &book.servers {
        let endpoint = book.endpoint_or_keyless(server);
        match list(&endpoint).await {
            Ok(instances) => {
                if let Some(instance) = pick(&instances, spec) {
                    hits.push(Resolved { server: server.clone(), instance, endpoint });
                }
            }
            Err(e) => failures.push(format!("  {} ({}): {e}", server.name, server.addr)),
        }
    }

    match hits.len() {
        1 => Ok(hits.pop().unwrap()),
        0 => {
            let mut msg = format!("no instance named '{spec}' on any known server");
            if !failures.is_empty() {
                msg.push_str("\nthese servers could not be reached:\n");
                msg.push_str(&failures.join("\n"));
            }
            bail!(msg)
        }
        _ => {
            let options = hits.iter().map(|h| format!("  {}", h.label())).collect::<Vec<_>>().join("\n");
            bail!("'{spec}' is ambiguous — name the server too:\n{options}")
        }
    }
}

fn pick(instances: &[InstanceStatResponse], spec: &str) -> Option<InstanceStatResponse> {
    instances.iter()
        .find(|i| i.name.eq_ignore_ascii_case(spec) || format!("{:032x}", i.id) == spec.to_lowercase())
        .cloned()
}

async fn list(endpoint: &Endpoint) -> anyhow::Result<Vec<InstanceStatResponse>> {
    match net::call(endpoint, Action::ListInstances).await {
        Ok(Response::InstanceList(list)) => Ok(list),
        Ok(other) => bail!("expected an instance list, got {other:?}"),
        Err(e) => bail!("{e}"),
    }
}
