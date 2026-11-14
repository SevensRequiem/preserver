#![windows_subsystem = "windows"]

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();
    preserver::gui::run()
}
