mod actions;
mod catalog;
pub mod cli;
mod config;
mod config_edit;
mod copy;
mod crypt;
mod daemon;
mod git;
#[cfg(feature = "gui")]
pub mod gui;
mod keys;
mod net;
mod paths;
mod personal;
mod platform;
mod public;
mod queue;
mod resolve;
mod schedule;
mod status;
#[cfg(test)]
mod testutil;
#[cfg_attr(
    windows,
    allow(dead_code, reason = "the Windows tray arrives in phase 5")
)]
mod tray_model;
mod verify;

pub use git::ssh::{SHIM, shim_main};
