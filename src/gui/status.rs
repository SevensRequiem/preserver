//! The Status page (live progress of every job) and the Actions page (one button per command,
//! the same list and enablement as the tray menu).

use super::{App, Done};
use crate::actions;
use crate::config::{Transport, save_transport};
use crate::queue::{JobState, Progress};
use eframe::egui;

/// How far a job is: bytes when it counts them, else files (repos, folders).
pub(super) fn fraction(p: &Progress) -> Option<f32> {
    let (done, total) = if p.bytes_total > 0 {
        (p.bytes_done, p.bytes_total)
    } else {
        (p.files_done, p.files_total)
    };
    #[expect(clippy::cast_precision_loss, reason = "a progress bar")]
    (total > 0).then(|| done.min(total) as f32 / total as f32)
}

#[expect(clippy::cast_precision_loss, reason = "a rate to one decimal")]
fn rate(bps: u64) -> Option<String> {
    (bps > 0).then(|| format!("{:.1} MB/s", bps as f64 / 1e6))
}

pub(super) fn page(app: &mut App, ui: &mut egui::Ui) {
    let Some(snap) = &app.snap else {
        return;
    };
    let m = &snap.model;
    ui.heading(&m.tooltip);
    ui.label(&m.last_label);
    if let Some(p) = &m.public_label {
        ui.label(p);
    }
    ui.label(&m.daemon_label);
    if let Some(q) = &m.queue_label {
        ui.label(q);
    }
    let pause = m.pause_label.map(|l| (l, !m.queue_paused));
    let items = m.jobs.clone();
    let jobs = snap.inputs.jobs.clone();
    if let Some((label, pause)) = pause
        && ui.button(label).clicked()
    {
        app.act(|p| actions::pause_all(p, pause).map(|()| label.to_string()));
    }
    ui.separator();
    if items.is_empty() {
        ui.label("Nothing queued.");
    }
    for item in items {
        let Some(job) = jobs.iter().find(|j| j.id == item.id) else {
            continue;
        };
        ui.group(|ui| {
            ui.strong(&item.label);
            if let Some(f) = fraction(&job.progress) {
                ui.add(egui::ProgressBar::new(f).show_percentage());
            }
            let mut line = Vec::new();
            if matches!(job.state, JobState::Running { .. }) {
                line.extend(rate(job.progress.rate_bps));
            }
            line.extend(job.progress.current.first().cloned());
            if !line.is_empty() {
                ui.weak(line.join("  "));
            }
            if let Some(e) = &job.error {
                ui.colored_label(ui.visuals().error_fg_color, e.as_str());
            }
            ui.horizontal(|ui| {
                if ui.button("Cancel").clicked() {
                    let id = item.id.clone();
                    app.act(|p| actions::cancel(p, &id).map(|()| format!("canceling {id}")));
                }
                // Retry mounts the job's drives, which may wait on polkit: off this thread.
                if item.retry && ui.button("Retry").clicked() {
                    let id = item.id.clone();
                    app.stale = true;
                    app.spawn(move |paths| {
                        Done::Said(
                            actions::retry(&paths, &id)
                                .map(|()| format!("retrying {id}"))
                                .map_err(|e| format!("{e:#}")),
                        )
                    });
                }
            });
        });
    }
}

pub(super) fn actions(app: &mut App, ui: &mut egui::Ui) {
    let Some(snap) = &app.snap else {
        return;
    };
    let commands = snap.model.commands.clone();
    let transport = snap.model.transport;
    let pause = snap.model.queue_paused;
    for c in commands {
        if ui
            .add_enabled(c.enabled, egui::Button::new(&c.label))
            .clicked()
        {
            app.run_command(c.cmd);
        }
    }
    ui.separator();
    let label = if pause { "Resume queue" } else { "Pause queue" };
    if ui.button(label).clicked() {
        app.act(|p| actions::pause_all(p, !pause).map(|()| label.to_string()));
    }
    if ui.button("Open archive folder").clicked() {
        app.spawn(|_| {
            Done::Said(
                actions::open_archive()
                    .map(|()| "opened".to_string())
                    .map_err(|e| format!("{e:#}")),
            )
        });
    }
    ui.separator();
    let Some(current) = transport else {
        ui.label("GitHub transport: config.toml does not load");
        return;
    };
    ui.horizontal(|ui| {
        ui.label("GitHub transport:");
        for t in [Transport::Ssh, Transport::Https] {
            if ui.radio(current == t, t.as_str()).clicked() && current != t {
                app.act(|p| {
                    save_transport(p, t).map(|()| format!("transport set to {}", t.as_str()))
                });
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_win_over_files() {
        let p = |fd, ft, bd, bt| Progress {
            files_done: fd,
            files_total: ft,
            bytes_done: bd,
            bytes_total: bt,
            ..Progress::default()
        };
        let cases = [
            ("nothing known", p(0, 0, 0, 0), None),
            ("repos", p(3, 4, 0, 0), Some(0.75)),
            ("bytes", p(1, 4, 50, 200), Some(0.25)),
            ("overshoot is clamped", p(0, 0, 300, 200), Some(1.0)),
        ];
        for (name, prog, want) in cases {
            assert_eq!(fraction(&prog), want, "{name}");
        }
        assert_eq!(rate(0), None);
        assert_eq!(rate(2_500_000).as_deref(), Some("2.5 MB/s"));
    }
}
