//! Wire types shared by the server and the client.
//!
//! Nothing in here may depend on the server's runtime crates (processkit,
//! gix, sysinfo) — that is the whole point of the split: the client links
//! only bierpc and these definitions.
//!
//! NOTE on named-field enum variants: `bier_derive` emits `Type::deserialize(…)`
//! for them, so generic field types must be written turbofish-style
//! (`Vec::<String>`), otherwise the generated code does not parse. Struct
//! fields and unnamed variant fields are wrapped properly and don't need it.

pub mod api;
pub mod auth;
pub mod instance;
pub mod session;
pub mod term;
pub mod tls;

pub use api::{Action, ApiError, DirEntry, ErrorCode, Response};
pub use auth::{AuthFailure, Reply, Request};
pub use session::{Session, SessionStart};
pub use instance::{
    ConsoleLine, GroupStats, InstanceConfig, InstanceStatResponse, InstanceStatus, RepoState,
    RetryPolicy, RunState, Source, Stream,
};
