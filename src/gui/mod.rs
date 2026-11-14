//! preserver-gui: one window over the same state and actions as the tray and the CLI. It reads
//! the status files and the queue, and every button calls the function the tray or CLI calls
//! (`actions`, `copy`, `public`, `config_edit`); nothing here writes state of its own. Long
//! actions run on std threads that send a `Done` back and wake the window.

mod copy;
mod public;
mod settings;
mod status;

use crate::actions;
use crate::copy::rules::Rule;
use crate::paths::Paths;
use crate::tray_model::{self, Command, Inputs, Model};
use eframe::egui;
use jiff::Timestamp;
use std::collections::HashMap;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::{Duration, Instant};

/// Opens the window and runs until it is closed.
///
/// # Errors
/// When no window or OpenGL context can be made.
pub fn run() -> anyhow::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_app_id("preserver")
            .with_title("preserver")
            .with_inner_size([860.0, 600.0]),
        ..Default::default()
    };
    eframe::run_native(
        "preserver",
        options,
        Box::new(|cc| Ok(Box::new(App::new(cc.egui_ctx.clone())))),
    )
    .map_err(|e| anyhow::anyhow!("open the window: {e}"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Page {
    Status,
    Actions,
    Settings,
    Copy,
    Public,
}

/// A finished background task.
enum Done {
    /// A command run: queued, or a `--foreground` child that exited.
    Ran(Command, Result<String, String>),
    /// Anything that only reports a line.
    Said(Result<String, String>),
    Plan(Result<String, String>),
    PublicList(Result<String, String>),
    Drives(Result<Vec<(String, String)>, String>),
    Saved(Result<String, String>),
}

/// The status files, queue and copy rules as last read.
struct Snapshot {
    inputs: Inputs,
    model: Model,
    rules: Vec<Rule>,
    last_runs: HashMap<String, Timestamp>,
    at: Instant,
}

struct App {
    ctx: egui::Context,
    paths: Result<Paths, String>,
    page: Page,
    snap: Option<Snapshot>,
    /// Re-read at the next frame, whatever the interval says.
    stale: bool,
    /// Command runs this window started that have not ended (the tray's `starting`).
    running: Vec<Command>,
    start_failure: Option<String>,
    toast: Option<Result<String, String>>,
    tx: Sender<Done>,
    rx: Receiver<Done>,
    drives: Vec<(String, String)>,
    settings: settings::Form,
    copy: copy::Form,
    public: Option<Result<String, String>>,
}

impl App {
    fn new(ctx: egui::Context) -> Self {
        let (tx, rx) = channel();
        Self {
            ctx,
            paths: Paths::from_env().map_err(|e| format!("{e:#}")),
            page: Page::Status,
            snap: None,
            stale: true,
            running: Vec::new(),
            start_failure: None,
            toast: None,
            tx,
            rx,
            drives: Vec::new(),
            settings: settings::Form::default(),
            copy: copy::Form::default(),
            public: None,
        }
    }

    /// Runs `f` on its own thread with a copy of the paths; its result comes back as a `Done`.
    fn spawn(&self, f: impl FnOnce(Paths) -> Done + Send + 'static) {
        let Ok(paths) = self.paths.clone() else {
            return;
        };
        let (tx, ctx) = (self.tx.clone(), self.ctx.clone());
        std::thread::spawn(move || {
            let _ = tx.send(f(paths));
            ctx.request_repaint();
        });
    }

    /// Does what the tray does for a command: queued for the daemon, or run here as a child.
    fn run_command(&mut self, cmd: Command) {
        self.running.push(cmd.clone());
        self.start_failure = None;
        self.stale = true;
        self.spawn(move |paths| {
            let r = actions::run(&paths, &cmd)
                .map(|()| "done".to_string())
                .map_err(|e| format!("{e:#}"));
            Done::Ran(cmd, r)
        });
    }

    /// A quick action on the UI thread: control files and the like.
    fn act(&mut self, f: impl FnOnce(&Paths) -> anyhow::Result<String>) {
        let Ok(paths) = &self.paths else {
            return;
        };
        self.toast = Some(f(paths).map_err(|e| format!("{e:#}")));
        self.stale = true;
    }

    /// Lists the drives the primary picker and copy targets offer, off the UI thread (udisks).
    fn find_drives(&self) {
        self.spawn(|paths| {
            Done::Drives(
                crate::platform::list_filesystems()
                    .map(|fss| {
                        let cfg = crate::config::Config::load(&paths.cfg).ok();
                        let registered: Vec<String> = crate::config::load_drives(&paths.drives_d)
                            .unwrap_or_default()
                            .into_iter()
                            .map(|d| d.id)
                            .collect();
                        drive_choices(&fss, &registered, cfg.as_ref().map(|c| &c.primary_uuid))
                    })
                    .map_err(|e| format!("list drives: {e:#}")),
            )
        });
    }

    fn drain(&mut self) {
        while let Ok(done) = self.rx.try_recv() {
            self.stale = true;
            match done {
                Done::Ran(cmd, r) => {
                    if let Some(at) = self.running.iter().position(|c| *c == cmd) {
                        self.running.remove(at);
                    }
                    if let Err(e) = &r {
                        self.start_failure = Some(e.clone());
                    }
                    self.toast = Some(r);
                }
                Done::Said(r) => self.toast = Some(r),
                Done::Plan(r) => self.copy.plan = Some(r),
                Done::PublicList(r) => self.public = Some(r),
                Done::Drives(Ok(d)) => self.drives = d,
                Done::Drives(Err(e)) => self.toast = Some(Err(e)),
                Done::Saved(r) => {
                    if r.is_ok() {
                        self.settings.loaded = None;
                    }
                    self.toast = Some(r);
                }
            }
        }
    }

    fn refresh(&mut self) {
        let Ok(paths) = &self.paths else {
            return;
        };
        let due = self
            .snap
            .as_ref()
            .is_none_or(|s| s.at.elapsed() >= tray_model::refresh_interval(&s.inputs.jobs));
        if !(due || self.stale) {
            return;
        }
        let inputs = actions::snapshot(paths, self.running.clone(), self.start_failure.clone());
        self.snap = Some(Snapshot {
            model: tray_model::model(&inputs),
            inputs,
            rules: crate::copy::rules::load(&paths.copy_rules).unwrap_or_default(),
            last_runs: crate::copy::last_runs(&paths.status_file("copy")),
            at: Instant::now(),
        });
        self.stale = false;
    }

    fn sidebar(&mut self, ui: &mut egui::Ui) {
        for (page, name) in [
            (Page::Status, "Status"),
            (Page::Actions, "Actions"),
            (Page::Settings, "Settings"),
            (Page::Copy, "Copy rules"),
            (Page::Public, "Public sets"),
        ] {
            ui.selectable_value(&mut self.page, page, name);
        }
    }

    fn toast(&mut self, ui: &mut egui::Ui) {
        let Some(t) = &self.toast else {
            return;
        };
        let close = ui
            .horizontal(|ui| {
                match t {
                    Ok(s) => ui.label(s.as_str()),
                    Err(e) => ui.colored_label(ui.visuals().error_fg_color, e.as_str()),
                };
                ui.small_button("x").clicked()
            })
            .inner;
        if close {
            self.toast = None;
        }
        ui.separator();
    }
}

impl eframe::App for App {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.drain();
        self.refresh();
        let wait = self.snap.as_ref().map_or(Duration::from_secs(1), |s| {
            tray_model::refresh_interval(&s.inputs.jobs)
        });
        ctx.request_repaint_after(wait);
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        egui::Panel::left("pages")
            .resizable(false)
            .show(ui, |ui| self.sidebar(ui));
        egui::CentralPanel::default().show(ui, |ui| {
            if let Err(e) = &self.paths {
                ui.colored_label(ui.visuals().error_fg_color, e.as_str());
                return;
            }
            self.toast(ui);
            egui::ScrollArea::vertical().show(ui, |ui| match self.page {
                Page::Status => status::page(self, ui),
                Page::Actions => status::actions(self, ui),
                Page::Settings => settings::page(self, ui),
                Page::Copy => copy::page(self, ui),
                Page::Public => public::page(self, ui),
            });
        });
    }
}

/// The filesystems `preserver drives` lists (removable, the primary, registered ones) as
/// (id, "id  label  fstype  size") for a picker; ids that do not parse are left out.
fn drive_choices(
    fss: &[crate::platform::FsInfo],
    registered: &[String],
    primary: Option<&crate::config::DriveId>,
) -> Vec<(String, String)> {
    fss.iter()
        .filter(|f| f.id.parse::<crate::config::DriveId>().is_ok())
        .filter(|f| {
            f.removable || primary.is_some_and(|p| p.matches(&f.id)) || registered.contains(&f.id)
        })
        .map(|f| {
            let label = format!(
                "{}  {}  {}  {}",
                f.id,
                f.label,
                f.fstype,
                crate::public::gb(f.size)
            );
            (f.id.clone(), label)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::FsInfo;

    #[test]
    fn drive_choices_match_the_drives_command() {
        let fs = |id: &str, removable| FsInfo {
            device: "/dev/x".into(),
            id: id.into(),
            label: "L".into(),
            fstype: "exfat".into(),
            size: 2_000_000_000,
            mount: None,
            removable,
        };
        let fss = [
            fs("AAAA-0001", true),
            fs("BBBB-0002", false),
            fs("CCCC-0003", false),
            fs("DDDD-0004", false),
            fs("not an id", true),
        ];
        let primary: crate::config::DriveId = "bbbb0002".parse().unwrap();
        let got = drive_choices(&fss, &["CCCC-0003".to_string()], Some(&primary));
        let ids: Vec<&str> = got.iter().map(|(id, _)| id.as_str()).collect();
        assert_eq!(ids, ["AAAA-0001", "BBBB-0002", "CCCC-0003"]);
        assert!(got[0].1.starts_with("AAAA-0001  L  exfat"), "{}", got[0].1);
    }
}
