mod catalog;
pub mod cli;
mod config;
mod crypt;
mod git;
mod keys;
mod migrate;
mod net;
mod paths;
mod personal;
mod platform;
mod public;
mod queue;
mod resolve;
mod status;
#[cfg(test)]
mod testutil;
#[cfg_attr(
    windows,
    allow(dead_code, reason = "the Windows tray arrives in phase 5")
)]
mod tray_model;
mod verify;

pub use git::credential::{HELPER, helper_main};
pub use git::ssh::{SHIM, shim_main};
