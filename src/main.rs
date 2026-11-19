use clap::Parser;
use preserver::cli::{Cli, run};
use std::path::Path;

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args_os();
    let argv0 = args.next().unwrap_or_default();
    // gix runs the binary under this name as its ssh program.
    if Path::new(&argv0).file_name().and_then(|n| n.to_str()) == Some(preserver::SHIM) {
        return Err(preserver::shim_main(args));
    }
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();
    run(Cli::parse())
}
