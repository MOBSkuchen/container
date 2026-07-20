//! Terminal client for container servers.
//!
//! Exposed as a library so headless drivers (`examples/tui_smoke.rs`) can
//! render the real UI against a `TestBackend` and drive the real state
//! machine, instead of the UI only ever being exercised by hand.

// Several net/form helpers land ahead of the screens that consume them
// (M2 manage screen, M3 terminals, M4 file browser).
#![allow(dead_code)]

pub mod app;
pub mod book;
pub mod console;
pub mod form;
pub mod instance_form;
pub mod net;
pub mod target;
pub mod terminal;
pub mod ui;
