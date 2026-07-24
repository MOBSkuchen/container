//! Terminal client for container servers.
//!
//! Exposed as a library so headless drivers (`examples/tui_smoke.rs`) can
//! render the real UI against a `TestBackend` and drive the real state
//! machine, instead of the UI only ever being exercised by hand

pub mod app;
pub mod book;
pub mod browse;
pub mod console;
pub mod editor;
pub mod form;
pub mod instance_form;
pub mod net;
pub mod target;
pub mod terminal;
pub mod transfer;
pub mod ui;
