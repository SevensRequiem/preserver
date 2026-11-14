use super::notify::{Reminder, notify};
use crate::config::{self, Config, Transport};
use crate::paths::Paths;
use crate::status::{Status, lock_held};
use crate::tray_model::{Inputs, Job, Model, model};
use anyhow::{Context, Result};
use ksni::blocking::TrayMethods;
use ksni::menu::{MenuItem, RadioGroup, RadioItem, StandardItem, SubMenu};
use std::process::{Command, Stdio};
use std::sync::mpsc::{RecvTimeoutError, Sender, channel};
use std::time::Duration;

const UNIT: &str = "preserver-personal.service";
const TRANSPORTS: [Transport; 2] = [Transport::Ssh, Transport::Https];

/// What the menu and the helper threads ask of the main loop, which owns every decision.
enum Cmd {
    Backup,
    BackupEnded { ok: bool },
    Open,
    Transport(Transport),
    Quit,
}

struct Tray {
    paths: Paths,
    tx: Sender<Cmd>,
    starting: bool,
    start_failure: Option<String>,
    model: Model,
}

fn read(paths: &Paths, starting: bool, start_failure: Option<String>) -> Model {
    let job = |name| {
        let status = Status::read(&paths.status_file(name));
        // The lock is only probed for a job that claims to run: probing takes it for an instant.
        let locked = status.running && lock_held(&paths.lock_file(name));
        Job { status, locked }
    };
    let now = jiff::Zoned::now();
    model(&Inputs {
        github: job("github"),
        local: job("local"),
        public: job("public"),
        starting,
        start_failure,
        today: now.date(),
        tz: now.time_zone().clone(),
        transport: Config::load(&paths.cfg).ok().map(|c| c.transport),
    })
}

impl Tray {
    fn refresh(&mut self) {
        self.model = read(&self.paths, self.starting, self.start_failure.clone());
    }

    fn send(&self, cmd: Cmd) {
        // The receiver lives as long as the process.
        let _ = self.tx.send(cmd);
    }
}

impl ksni::Tray for Tray {
    // A left click opens the menu.
    const MENU_ON_ACTIVATE: bool = true;

    fn id(&self) -> String {
        "preserver".into()
    }

    fn title(&self) -> String {
        "Code archive".into()
    }

    fn status(&self) -> ksni::Status {
        if self.model.state.needs_attention() {
            ksni::Status::NeedsAttention
        } else {
            ksni::Status::Active
        }
    }

    fn icon_name(&self) -> String {
        self.model.state.icon().into()
    }

    fn attention_icon_name(&self) -> String {
        self.model.state.icon().into()
    }

    fn tool_tip(&self) -> ksni::ToolTip {
        ksni::ToolTip {
            title: "Code archive".into(),
            description: self.model.tooltip.clone(),
            ..Default::default()
        }
    }

    /// A run from a terminal shows up when the menu opens, without waiting for the hourly tick.
    fn menu_about_to_show(&mut self) {
        self.refresh();
    }

    fn menu(&self) -> Vec<MenuItem<Self>> {
        let info = |label: &str| -> MenuItem<Self> {
            StandardItem {
                label: label.into(),
                enabled: false,
                ..Default::default()
            }
            .into()
        };
        let action = |label: &str, icon: &str, enabled: bool, cmd: fn() -> Cmd| -> MenuItem<Self> {
            StandardItem {
                label: label.into(),
                icon_name: icon.into(),
                enabled,
                activate: Box::new(move |tray: &mut Self| tray.send(cmd())),
                ..Default::default()
            }
            .into()
        };
        let m = &self.model;
        let mut items = vec![
            action(m.run_label, "folder-download", m.run_enabled(), || {
                Cmd::Backup
            }),
            info(&m.last_label),
        ];
        items.extend(m.public_label.as_deref().map(info));
        items.push(MenuItem::Separator);
        if let Some(current) = m.transport {
            let group = RadioGroup {
                selected: TRANSPORTS.iter().position(|t| *t == current).unwrap_or(0),
                select: Box::new(|tray: &mut Self, i| tray.send(Cmd::Transport(TRANSPORTS[i]))),
                options: TRANSPORTS
                    .iter()
                    .map(|t| RadioItem {
                        label: t.as_str().into(),
                        ..Default::default()
                    })
                    .collect(),
            };
            items.push(
                SubMenu {
                    label: "GitHub transport".into(),
                    submenu: vec![group.into()],
                    ..Default::default()
                }
                .into(),
            );
        }
        items.push(action("Open archive folder", "folder-open", true, || {
            Cmd::Open
        }));
        items.push(action("Quit", "application-exit", true, || Cmd::Quit));
        items
    }
}

/// Starts the backup unit and waits for it: the exit status is the only sign of a
/// run that failed before it wrote its status file.
fn run_unit() -> bool {
    // The unit runs under the user manager, so hand it the session's display for ksshaskpass.
    let _ = Command::new("systemctl")
        .args([
            "--user",
            "import-environment",
            "DISPLAY",
            "WAYLAND_DISPLAY",
            "XAUTHORITY",
        ])
        .stdin(Stdio::null())
        .status();
    Command::new("systemctl")
        .args(["--user", "start", UNIT])
        .stdin(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

fn open_folder() {
    let opened = std::env::current_exe()
        .and_then(|exe| Command::new(exe).arg("open").stdin(Stdio::null()).status());
    if !opened.is_ok_and(|s| s.success()) {
        tracing::error!("open the archive folder failed");
    }
}

pub(crate) fn run_tray(paths: &Paths) -> Result<()> {
    let (tx, rx) = channel();
    let tray = Tray {
        model: read(paths, false, None),
        paths: paths.clone(),
        tx: tx.clone(),
        starting: false,
        start_failure: None,
    };
    // The unit may start before the panel does; ksni registers once the watcher appears, and
    // again whenever it comes back (a plasmashell restart forgets every item).
    let handle = tray
        .assume_sni_available(true)
        .spawn()
        .context("start the tray")?;
    let reminder_tx = tx.clone();
    let reminder = Reminder::new(move || {
        let _ = reminder_tx.send(Cmd::Backup);
    })
    .inspect_err(|e| tracing::warn!("no reminders: {e:#}"))
    .ok();
    let mut last_shown = None;

    loop {
        let (due, last) = handle
            .update(|t| {
                t.refresh();
                (t.model.reminder_due(), t.model.last_label.clone())
            })
            .context("the tray service stopped")?;
        let today = jiff::Zoned::now().date();
        if due && last_shown != Some(today) {
            last_shown = Some(today);
            if let Some(reminder) = reminder.clone() {
                // Off this thread: a notification server that hangs must not freeze the menu.
                std::thread::spawn(move || reminder.show(&format!("{last}.")));
            }
        }

        match rx.recv_timeout(Duration::from_secs(3600)) {
            Ok(Cmd::Backup) => {
                let start = handle.update(|t| {
                    let idle = t.model.run_enabled();
                    if idle {
                        t.starting = true;
                        t.start_failure = None;
                    }
                    idle
                });
                if start == Some(true) {
                    let tx = tx.clone();
                    std::thread::spawn(move || tx.send(Cmd::BackupEnded { ok: run_unit() }));
                }
            }
            Ok(Cmd::BackupEnded { ok }) => {
                handle.update(|t| {
                    t.starting = false;
                    if !ok {
                        t.start_failure = Some(format!("see journalctl --user -u {UNIT}"));
                    }
                });
            }
            Ok(Cmd::Open) => {
                std::thread::spawn(open_folder);
            }
            Ok(Cmd::Transport(transport)) => {
                if let Err(e) = config::save_transport(&paths.cfg, transport) {
                    tracing::error!("set the transport: {e:#}");
                    notify(true, "GitHub transport not changed", &format!("{e:#}"));
                }
            }
            Ok(Cmd::Quit) | Err(RecvTimeoutError::Disconnected) => return Ok(()),
            Err(RecvTimeoutError::Timeout) => {}
        }
    }
}
