//! The Public sets page: `preserver public --list` (priority, variants, estimated and measured
//! sizes) and "Mirror all now".

use super::{App, Done};
use crate::config::Config;
use crate::public;
use crate::tray_model::Command;
use eframe::egui;

pub(super) fn page(app: &mut App, ui: &mut egui::Ui) {
    let mirror = app.snap.as_ref().and_then(|s| {
        s.model
            .commands
            .iter()
            .find(|c| c.cmd == Command::Public)
            .cloned()
    });
    let mut refresh = app.public.is_none();
    ui.horizontal(|ui| {
        // Refresh mounts the primary to measure it, as `public --list` does.
        refresh |= ui.button("Refresh").clicked();
        if let Some(c) = &mirror
            && ui
                .add_enabled(c.enabled, egui::Button::new("Mirror all now"))
                .clicked()
        {
            app.run_command(Command::Public);
        }
    });
    match &app.public {
        Some(Ok(t)) => {
            ui.monospace(t.as_str());
        }
        Some(Err(e)) => {
            ui.colored_label(ui.visuals().error_fg_color, e.as_str());
        }
        None => {
            ui.spinner();
        }
    }
    if refresh {
        app.public = Some(Ok("reading the catalog and the drive…".into()));
        app.spawn(|mut paths| {
            Done::PublicList(
                Config::load(&paths.cfg)
                    .and_then(|cfg| public::list_report(&mut paths, &cfg))
                    .map_err(|e| format!("{e:#}")),
            )
        });
    }
}
