//! Side-channel session requests, carried over bierpc's persistent-call path.
//!
//! A session runs on the same mutually-authenticated TLS connection as unary
//! RPC (see `crate::tls`). Because that connection authenticates the client by
//! itself, a `Session` carries no per-request HMAC — unlike a unary `Action`.
//!
//! The wire dance, once bierpc has accepted the persistent call:
//!   1. server → client: `Result<SessionStart, ApiError>` — validation result,
//!      replacing the old unary rejection.
//!   2. the session runs (transfers self-delimit with a length prefix;
//!      terminals frame both ways and end with `term::Close`).
//!   3. server → client: the persistent call's reply (`Response::Done`/`Error`).

use std::path::PathBuf;
use bier_derive::{Deserialize, Serialize};
use bierpc::serialize::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub enum Session {
    /// Bridge to a running instance's stdin/stdout (pipe-based, line-oriented).
    Attach(u128),
    /// A fresh PTY shell in the instance's repo dir, sized `cols` x `rows`.
    Shell { id: u128, cols: u16, rows: u16 },
    /// Push a single file to `dest`.
    UploadFile { dest: PathBuf },
    /// Pull a single file from `src`.
    DownloadFile { src: PathBuf },
    /// Push a tar.gz and unpack it into `dest`.
    UploadArchive { dest: PathBuf },
    /// Pack `paths` server-side and stream the tar.gz back.
    DownloadArchive { paths: Vec::<PathBuf> },
    /// Push a tar.gz as an Upload-source instance's content.
    UploadSource { id: u128 },
}

/// What the client needs before the session bytes flow. Sent as
/// `Result<SessionStart, ApiError>`; the error arm carries a rejection.
#[derive(Serialize, Deserialize, Debug)]
pub struct SessionStart {
    /// A download's total length when known up front (a single file); `None`
    /// when it is only known once streaming starts (an archive packed live).
    pub size: Option::<u64>,
}
