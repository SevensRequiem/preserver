pub mod cli;
mod config;
mod crypt;
mod git;
mod migrate;
mod paths;
mod personal;
mod platform;
mod status;
#[cfg(test)]
mod testutil;

pub use git::credential::{HELPER, helper_main};
pub use git::ssh::{SHIM, shim_main};
