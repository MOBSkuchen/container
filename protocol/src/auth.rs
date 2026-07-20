//! Pre-shared-key authentication for the RPC channel.
//!
//! Both ends hold the same 1024-byte key, produced by `keygen` on either side:
//! from a passphrase (SHAKE256, so the same phrase gives the same key on both
//! machines) or from OS entropy (so it must then be copied across).
//!
//! Every request carries an HMAC-SHA256 over `nonce || timestamp || payload`,
//! and the reply is signed over the *request's* nonce, which binds it to the
//! request it answers. The action itself travels as an opaque blob and is
//! deserialized only after the MAC verifies — so untrusted bytes never reach
//! the decoder, and the MAC does not depend on serialization being canonical
//! (`HashMap` field order is not).
//!
//! This authenticates; it does not encrypt. Anyone on the path can still read
//! instance names, repo URLs and console output. It stops unauthorized
//! *control* of a server, which is the point.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bier_derive::{Deserialize, Serialize};
use bierpc::serialize::{Deserialize, Serialize};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use sha3::Shake256;

pub const KEY_LEN: usize = 1024;

/// How far apart the two clocks may be before a request is refused. Also the
/// window a nonce must be remembered for.
pub const MAX_SKEW: Duration = Duration::from_secs(60);

const NONCE_LEN: usize = 16;

/// Derive a key from `input`, or draw a fresh random one when it is absent or
/// empty. SHAKE256 is an extendable-output function, so the full 1024 bytes
/// come straight from the sponge.
pub fn hash_or_random(input: Option<&str>) -> [u8; KEY_LEN] {
    // Scoped: `digest::Update::update` would otherwise collide with
    // `hmac::Mac::update` on the HMAC calls below.
    use sha3::digest::{ExtendableOutput, Update, XofReader};

    let mut output = [0u8; KEY_LEN];

    match input {
        Some(text) if !text.is_empty() => {
            let mut hasher = Shake256::default();
            hasher.update(text.as_bytes());
            let mut reader = hasher.finalize_xof();
            reader.read(&mut output);
        }
        _ => {
            getrandom::fill(&mut output).expect("the OS refused to provide entropy");
        }
    }

    output
}

/// Why a request was refused before its payload could be trusted.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq)]
pub enum AuthFailure {
    /// The MAC did not verify: wrong key, or tampering.
    BadKey,
    /// Outside the clock-skew window.
    Stale,
    /// This nonce was already used.
    Replay,
    /// Structurally wrong (bad nonce length, undecodable payload).
    Malformed,
}

impl std::fmt::Display for AuthFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            AuthFailure::BadKey => "the server rejected this client's key — run `keygen` with the same phrase on both sides",
            AuthFailure::Stale => "the request was outside the 60s clock-skew window — check the clocks on both machines",
            AuthFailure::Replay => "that request nonce was already used",
            AuthFailure::Malformed => "the request was malformed",
        })
    }
}

/// A signed, opaque payload. `payload` is a serialized `Action`.
#[derive(Serialize, Deserialize, Debug)]
pub struct Request {
    pub nonce: Vec::<u8>,
    pub timestamp_ms: u64,
    pub mac: Vec::<u8>,
    pub payload: Vec::<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum Reply {
    /// `payload` is a serialized `Response`, signed against the request nonce.
    Signed {
        timestamp_ms: u64,
        mac: Vec::<u8>,
        payload: Vec::<u8>,
    },
    /// Refused before the request could be trusted, so this cannot be signed
    /// in a way the client could distinguish from an attacker's forgery. It
    /// is a hint for the operator, never a basis for a security decision.
    Rejected(AuthFailure),
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

fn tag(key: &[u8], nonce: &[u8], timestamp_ms: u64, payload: &[u8]) -> Vec<u8> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key)
        .expect("HMAC accepts keys of any length");
    mac.update(nonce);
    mac.update(&timestamp_ms.to_be_bytes());
    mac.update(payload);
    mac.finalize().into_bytes().to_vec()
}

fn verify_tag(key: &[u8], nonce: &[u8], timestamp_ms: u64, payload: &[u8], expected: &[u8]) -> bool {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key)
        .expect("HMAC accepts keys of any length");
    mac.update(nonce);
    mac.update(&timestamp_ms.to_be_bytes());
    mac.update(payload);
    // `verify_slice` compares in constant time.
    mac.verify_slice(expected).is_ok()
}

fn fresh(timestamp_ms: u64) -> bool {
    let now = now_ms();
    let skew = now.abs_diff(timestamp_ms);
    skew <= MAX_SKEW.as_millis() as u64
}

/// The MAC a request with these fields must carry. Exposed so tests can build
/// deliberately-wrong requests without duplicating the construction here —
/// duplicated crypto in a test drifts and then passes for the wrong reason.
pub fn request_mac(key: &[u8], nonce: &[u8], timestamp_ms: u64, payload: &[u8]) -> Vec<u8> {
    tag(key, nonce, timestamp_ms, payload)
}

pub fn sign_request(key: &[u8], payload: Vec<u8>) -> Request {
    let mut nonce = vec![0u8; NONCE_LEN];
    getrandom::fill(&mut nonce).expect("the OS refused to provide entropy");
    let timestamp_ms = now_ms();
    let mac = tag(key, &nonce, timestamp_ms, &payload);
    Request { nonce, timestamp_ms, mac, payload }
}

/// Verify a request and hand back its payload bytes. Order matters: shape,
/// then MAC, then freshness, then replay — a nonce is only worth burning once
/// the request is known to be authentic.
pub fn verify_request<'a>(
    key: &[u8],
    request: &'a Request,
    replay: &ReplayGuard,
) -> Result<&'a [u8], AuthFailure> {
    if request.nonce.len() != NONCE_LEN {
        return Err(AuthFailure::Malformed);
    }
    if !verify_tag(key, &request.nonce, request.timestamp_ms, &request.payload, &request.mac) {
        return Err(AuthFailure::BadKey);
    }
    if !fresh(request.timestamp_ms) {
        return Err(AuthFailure::Stale);
    }
    if !replay.remember(&request.nonce) {
        return Err(AuthFailure::Replay);
    }
    Ok(&request.payload)
}

/// Sign a reply against the nonce of the request it answers, so a reply
/// cannot be lifted from one exchange and replayed into another.
pub fn sign_reply(key: &[u8], request_nonce: &[u8], payload: Vec<u8>) -> Reply {
    let timestamp_ms = now_ms();
    let mac = tag(key, request_nonce, timestamp_ms, &payload);
    Reply::Signed { timestamp_ms, mac, payload }
}

pub fn verify_reply<'a>(
    key: &[u8],
    request_nonce: &[u8],
    reply: &'a Reply,
) -> Result<&'a [u8], AuthFailure> {
    match reply {
        Reply::Rejected(failure) => Err(*failure),
        Reply::Signed { timestamp_ms, mac, payload } => {
            if !verify_tag(key, request_nonce, *timestamp_ms, payload, mac) {
                return Err(AuthFailure::BadKey);
            }
            if !fresh(*timestamp_ms) {
                return Err(AuthFailure::Stale);
            }
            Ok(payload)
        }
    }
}

/// Remembers recently seen nonces so a captured request cannot be resent.
///
/// Entries only need to outlive the skew window: anything older is already
/// refused as stale, so it can be forgotten.
pub struct ReplayGuard {
    seen: Mutex<HashMap<Vec<u8>, Instant>>,
}

impl Default for ReplayGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplayGuard {
    pub fn new() -> Self {
        Self { seen: Mutex::new(HashMap::new()) }
    }

    /// Record `nonce`; false if it had already been used.
    pub fn remember(&self, nonce: &[u8]) -> bool {
        let horizon = MAX_SKEW * 2;
        let now = Instant::now();
        let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        seen.retain(|_, at| now.duration_since(*at) < horizon);
        seen.insert(nonce.to_vec(), now).is_none()
    }
}

// ---- key transport ----------------------------------------------------

pub fn to_hex(key: &[u8]) -> String {
    key.iter().map(|b| format!("{b:02x}")).collect()
}

/// Parse a hex key, checking the length here so callers get one clear error
/// rather than a confusing MAC failure later.
pub fn from_hex(text: &str) -> Result<Vec<u8>, String> {
    let text = text.trim();
    if text.len() != KEY_LEN * 2 {
        return Err(format!(
            "a key is {} hex characters ({KEY_LEN} bytes); got {}",
            KEY_LEN * 2, text.len(),
        ));
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16)
            .map_err(|_| format!("'{}' is not a hex byte", &text[i..i + 2])))
        .collect()
}

// ---- payload codec ----------------------------------------------------

/// Serialize a wire value to bytes. `Vec<u8>` is an `AsyncWrite`, so this
/// reuses the same encoding the socket would have seen.
pub async fn encode<T: Serialize + Sync>(value: &T) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    value.serialize(&mut buf).await?;
    Ok(buf)
}

pub async fn decode<T: Deserialize>(bytes: &[u8]) -> std::io::Result<T> {
    T::deserialize(bytes).await
}
