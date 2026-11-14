use super::notify::{Reminder, notify};
use crate::actions;
use crate::config::{self, Transport};
use crate::paths::Paths;
use crate::tray_model::{Command, JobItem, Model, gui_path, model};
use anyhow::{Context, Result};
use ksni::blocking::TrayMethods;
use ksni::menu::{MenuItem, RadioGroup, RadioItem, StandardItem, SubMenu};
use std::collections::HashSet;
use std::process::{Command as Process, Stdio};
use std::sync::mpsc::{RecvTimeoutError, Sender, channel};

const TRANSPORTS: [Transport; 2] = [Transport::Ssh, Transport::Https];

/// What the menu and the helper threads ask of the main loop, which owns every decision.
enum Cmd {
    Run(Command),
    RunEnded {
        cmd: Command,
        ok: bool,
    },
    Open,
    OpenGui,
    Transport(Transport),
    /// Pause (true) or resume the whole queue through `all.ctl`.
    QueuePause(bool),
    Cancel(String),
    Retry(String),
    Quit,
}

struct Tray {
    paths: Paths,
    tx: Sender<Cmd>,
    /// Runs the tray started that have not ended, one entry each.
    starting: Vec<Command>,
    start_failure: Option<String>,
    model: Model,
}

fn read(paths: &Paths, starting: Vec<Command>, start_failure: Option<String>) -> Model {
    model(&actions::snapshot(paths, starting, start_failure))
}

impl Tray {
    fn refresh(&mut self) {
        self.model = read(
            &self.paths,
            self.starting.clone(),
            self.start_failure.clone(),
        );
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
        "preserver".into()
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
            title: "preserver".into(),
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
        let mut items: Vec<MenuItem<Self>> = m
            .commands
            .iter()
            .map(|c| {
                let cmd = c.cmd.clone();
                StandardItem {
                    label: c.label.clone(),
                    icon_name: "folder-download".into(),
                    enabled: c.enabled,
                    activate: Box::new(move |tray: &mut Self| tray.send(Cmd::Run(cmd.clone()))),
                    ..Default::default()
                }
                .into()
            })
            .collect();
        items.push(MenuItem::Separator);
        items.push(info(&m.last_label));
        items.extend(m.public_label.as_deref().map(info));
        items.push(info(&m.daemon_label));
        items.extend(m.queue_label.as_deref().map(info));
        if let Some(label) = m.pause_label {
            let pause = !m.queue_paused;
            items.push(
                StandardItem {
                    label: label.into(),
                    icon_name: if pause {
                        "media-playback-pause"
                    } else {
                        "media-playback-start"
                    }
                    .into(),
                    activate: Box::new(move |tray: &mut Self| tray.send(Cmd::QueuePause(pause))),
                    ..Default::default()
                }
                .into(),
            );
        }
        items.extend(m.jobs.iter().map(job_menu));
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
        items.push(action("Open preserver", "preferences-system", true, || {
            Cmd::OpenGui
        }));
        items.push(action("Quit", "application-exit", true, || Cmd::Quit));
        items
    }
}

fn open_folder() {
    if let Err(e) = actions::open_archive() {
        tracing::error!("open the archive folder: {e:#}");
    }
}

/// Starts preserver-gui next to this binary and reaps it on a thread, so the loop never waits.
fn open_gui() {
    let gui = std::env::current_exe().map(|exe| gui_path(&exe));
    let child = match gui {
        Ok(gui) if gui.is_file() => Process::new(gui).stdin(Stdio::null()).spawn(),
        _ => {
            notify(
                true,
                "preserver-gui is not installed",
                "Install it with install.sh from a release that ships preserver-gui.",
            );
            return;
        }
    };
    match child {
        Ok(mut child) => {
            std::thread::spawn(move || child.wait());
        }
        Err(e) => {
            tracing::error!("start preserver-gui: {e}");
            notify(true, "preserver-gui did not start", &e.to_string());
        }
    }
}

/// The daemon reads these from the user manager per job, for ssh's askpass dialog.
fn import_session() {
    let imported = Process::new("systemctl")
        .args([
            "--user",
            "import-environment",
            "DISPLAY",
            "WAYLAND_DISPLAY",
            "XAUTHORITY",
        ])
        .stdin(Stdio::null())
        .status();
    if !imported.is_ok_and(|s| s.success()) {
        tracing::warn!(
            "systemctl --user import-environment failed: the daemon cannot ask for the security key"
        );
    }
}

pub(crate) fn run_tray(paths: &Paths) -> Result<()> {
    import_session();
    let (tx, rx) = channel();
    let tray = Tray {
        model: read(paths, Vec::new(), None),
        paths: paths.clone(),
        tx: tx.clone(),
        starting: Vec::new(),
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
        let _ = reminder_tx.send(Cmd::Run(Command::Personal));
    })
    .inspect_err(|e| tracing::warn!("no reminders: {e:#}"))
    .ok();
    let mut last_shown = None;
    let mut touch_shown = HashSet::new();

    loop {
        let (due, last, poll, touch) = handle
            .update(|t| {
                t.refresh();
                (
                    t.model.reminder_due(),
                    t.model.last_label.clone(),
                    t.model.poll,
                    t.model.touch_needed.clone(),
                )
            })
            .context("the tray service stopped")?;
        let today = jiff::Zoned::now().date();
        if due && last_shown != Some(today) {
            last_shown = Some(today);
            if let Some(reminder) = reminder.clone() {
                // Off this thread: a notification server that hangs must not freeze the menu.
                std::thread::spawn(move || {
                    reminder.show("Personal backup overdue", &format!("{last}."));
                });
            }
        }
        if let Some(id) = touch
            && touch_shown.insert(id)
            && let Some(reminder) = reminder.clone()
        {
            std::thread::spawn(move || {
                reminder.show(
                    "GitHub backup is waiting for your security key",
                    "Touch the key when asked, or press Back up now to ask again.",
                );
            });
        }

        match rx.recv_timeout(poll) {
            Ok(Cmd::Run(cmd)) => {
                handle.update(|t| {
                    t.starting.push(cmd.clone());
                    t.start_failure = None;
                });
                // Off this thread: a foreground run lasts as long as the backup, and a mount
                // may wait on polkit.
                let (tx, paths) = (tx.clone(), paths.clone());
                std::thread::spawn(move || {
                    let ok = actions::run(&paths, &cmd)
                        .inspect_err(|e| tracing::error!("run {cmd:?}: {e:#}"))
                        .is_ok();
                    let _ = tx.send(Cmd::RunEnded { cmd, ok });
                });
            }
            Ok(Cmd::RunEnded { cmd, ok }) => {
                handle.update(|t| {
                    if let Some(at) = t.starting.iter().position(|c| *c == cmd) {
                        t.starting.remove(at);
                    }
                    if !ok {
                        t.start_failure =
                            Some("see journalctl --user -u preserver-tray.service".into());
                    }
                });
            }
            Ok(Cmd::OpenGui) => open_gui(),
            Ok(Cmd::Open) => {
                std::thread::spawn(open_folder);
            }
            Ok(cmd @ (Cmd::Transport(_) | Cmd::QueuePause(_) | Cmd::Cancel(_) | Cmd::Retry(_))) => {
                queue_cmd(paths, cmd);
            }
            Ok(Cmd::Quit) | Err(RecvTimeoutError::Disconnected) => return Ok(()),
            Err(RecvTimeoutError::Timeout) => {}
        }
    }
}

/// The menu entries that only touch config.toml or the queue's control files.
fn queue_cmd(paths: &Paths, cmd: Cmd) {
    match cmd {
        Cmd::Transport(transport) => {
            if let Err(e) = config::save_transport(paths, transport) {
                tracing::error!("set the transport: {e:#}");
                notify(true, "GitHub transport not changed", &format!("{e:#}"));
            }
        }
        Cmd::QueuePause(pause) => {
            if let Err(e) = actions::pause_all(paths, pause) {
                tracing::error!("pause the queue: {e:#}");
            }
        }
        Cmd::Cancel(id) => {
            if let Err(e) = actions::cancel(paths, &id) {
                tracing::error!("cancel {id}: {e:#}");
            }
        }
        Cmd::Retry(id) => {
            // Off this thread: the mount may wait on polkit.
            let paths = paths.clone();
            std::thread::spawn(move || {
                if let Err(e) = actions::retry(&paths, &id) {
                    tracing::error!("retry {id}: {e:#}");
                }
            });
        }
        _ => {}
    }
}

/// A job's entry: its line, and cancel and retry under it.
fn job_menu(c: &JobItem) -> MenuItem<Tray> {
    let (cancel, retry) = (c.id.clone(), c.id.clone());
    let mut submenu: Vec<MenuItem<Tray>> = vec![
        StandardItem {
            label: "Cancel".into(),
            icon_name: "process-stop".into(),
            activate: Box::new(move |tray: &mut Tray| {
                tray.send(Cmd::Cancel(cancel.clone()));
            }),
            ..Default::default()
        }
        .into(),
    ];
    if c.retry {
        submenu.push(
            StandardItem {
                label: "Retry".into(),
                icon_name: "view-refresh".into(),
                activate: Box::new(move |tray: &mut Tray| {
                    tray.send(Cmd::Retry(retry.clone()));
                }),
                ..Default::default()
            }
            .into(),
        );
    }
    SubMenu {
        label: c.label.clone(),
        submenu,
        ..Default::default()
    }
    .into()
}
