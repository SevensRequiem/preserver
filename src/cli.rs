use crate::config::{Config, Transport, load_drives};
use crate::paths::Paths;
use crate::{personal, platform, public, queue};
use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "preserver", version, about)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum Tier {
    Usb64,
    Disk1t,
    Full,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Create the age key (asks for the restore password), or take over an existing one
    Init {
        /// A passphrase-locked identity.age to copy instead of generating a new key
        #[arg(long, value_name = "IDENTITY_AGE")]
        import: Option<PathBuf>,
    },
    /// Back up GitHub repositories and local folders
    Personal {
        #[arg(long)]
        local_only: bool,
        /// GitHub transport, overriding config.toml
        #[arg(long, value_enum)]
        transport: Option<Transport>,
    },
    /// Restore a .bundle.age (git repo) or a .tar.zst.age (local folder; a Dnn needs its L0 next to it) into DIR. Symlinks with an absolute target or one that climbs out of DIR are not recreated: they are listed and the exit status is non-zero
    Restore { file: PathBuf, dir: PathBuf },
    /// Mirror the public archive sets
    Public {
        sets: Vec<String>,
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        first_pass: bool,
    },
    /// Inspect and control the job queue
    Queue {
        #[command(subcommand)]
        action: QueueAction,
    },
    /// Copy the archive to another drive
    Clone {
        dest: PathBuf,
        #[arg(long, value_enum)]
        tier: Option<Tier>,
        #[arg(long, value_delimiter = ',')]
        sets: Vec<String>,
        #[arg(long)]
        once: bool,
    },
    /// Verify archive checksums
    Verify {
        #[arg(long)]
        repair: bool,
    },
    /// List the primary, registered and removable drives
    Drives,
    /// Mount the backup drive and open the archive folder
    Open,
    /// Run the tray icon
    Tray,
    /// Install scheduled tasks (Windows)
    Install,
}

#[derive(Debug, Subcommand)]
pub enum QueueAction {
    List {
        #[arg(long)]
        watch: bool,
    },
    Show {
        id: String,
    },
    Pause {
        id: Option<String>,
        #[arg(long)]
        all: bool,
    },
    Resume {
        id: Option<String>,
        #[arg(long)]
        all: bool,
        #[arg(long)]
        drive: Option<String>,
    },
    Cancel {
        id: String,
    },
    Retry {
        id: String,
    },
    Prio {
        id: String,
        priority: u32,
    },
    Run,
}

fn drives(paths: &Paths, cfg: &Config) -> Result<()> {
    let registered = load_drives(&paths.drives_d)?;
    println!(
        "primary: {} (mount {}, mounted: {})",
        cfg.primary_uuid,
        paths.mnt.display(),
        platform::is_mounted(&paths.mnt)
    );
    println!("registered:");
    for d in &registered {
        println!("  {}  {}  {}", d.id, d.role, d.label);
    }
    let filesystems = platform::list_filesystems().context("udisks2")?;
    println!("filesystems udisks2 sees (removable, primary or registered):");
    for f in filesystems {
        let known = cfg.primary_uuid.matches(&f.id) || registered.iter().any(|d| d.id == f.id);
        if !f.removable && !known {
            continue;
        }
        #[expect(
            clippy::cast_precision_loss,
            reason = "a size shown to one decimal place"
        )]
        let gib = f.size as f64 / f64::from(1u32 << 30);
        println!(
            "  {:<14} {:<36} {:<6} {gib:8.1} GiB  {:<12} {}",
            f.device,
            f.id,
            f.fstype,
            f.label,
            f.mount.map(|m| m.display().to_string()).unwrap_or_default()
        );
    }
    Ok(())
}

fn load() -> Result<(Paths, Config)> {
    let mut paths = Paths::from_env()?;
    let cfg = Config::load(&paths.cfg)?;
    paths.set_drive(&cfg.primary_uuid);
    Ok((paths, cfg))
}

/// # Errors
/// Returns the failure of the subcommand, or "not implemented yet" for the ones of later phases.
pub fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Init { import } => {
            let (mut paths, cfg) = load()?;
            personal::init(&mut paths, &cfg, import.as_deref())
        }
        Command::Personal {
            local_only,
            transport,
        } => {
            let (mut paths, cfg) = load()?;
            let transport = transport.unwrap_or(cfg.transport);
            personal::run(&mut paths, &cfg, local_only, transport)
        }
        Command::Restore { file, dir } => {
            let mut paths = Paths::from_env()?;
            // Restore only needs the config to find the drive; a recovery host may have none.
            if paths.cfg.join("config.toml").exists() {
                paths.set_drive(&Config::load(&paths.cfg)?.primary_uuid);
            }
            personal::restore::run(&paths, &file, &dir)
        }
        Command::Drives => {
            let (paths, cfg) = load()?;
            drives(&paths, &cfg)
        }
        Command::Open => {
            let (mut paths, cfg) = load()?;
            paths.mount(&cfg.primary_uuid)?;
            let archive = paths.archive();
            platform::private_dir_all(&archive)?;
            platform::open_path(&archive)
        }
        Command::Tray => platform::run_tray(&Paths::from_env()?),
        Command::Queue { action } => queue::cli(&Paths::from_env()?, action),
        Command::Public {
            sets,
            dry_run,
            first_pass,
        } => {
            let (mut paths, cfg) = load()?;
            public::run(&mut paths, &cfg, &sets, dry_run, first_pass)
        }
        Command::Clone { .. } | Command::Verify { .. } => bail!("not implemented yet (phase 4)"),
        Command::Install => bail!("not implemented yet (phase 5)"),
    }
}
