//! The Copy rules page: the saved rules with their last run, run or remove one, and add one
//! or preview its plan through the functions `preserver copy` uses.

use super::{App, Done};
use crate::catalog::Catalog;
use crate::config::Config;
use crate::copy::{self, rules};
use crate::paths::Paths;
use crate::queue::Store;
use crate::tray_model::Command;
use anyhow::Result;
use eframe::egui;

#[derive(Default)]
pub(super) struct Form {
    target: String,
    every: String,
    sets: String,
    size: String,
    pub plan: Option<Result<String, String>>,
}

/// Set names and groups as typed: commas or spaces between them.
pub(super) fn tokens(s: &str) -> Vec<String> {
    s.split([',', ' '])
        .filter(|t| !t.is_empty())
        .map(str::to_string)
        .collect()
}

/// What `preserver copy TARGET [-s SETS] [--size N]` resolves before it plans or saves.
fn request(
    paths: &Paths,
    target: &str,
    sets: &str,
    size: &str,
) -> Result<(Config, crate::queue::Target, Vec<String>, Option<u64>)> {
    let cfg = Config::load(&paths.cfg)?;
    let sets = rules::resolve_sets(&Catalog::embedded()?, &tokens(sets))?;
    let size = Some(size.trim())
        .filter(|s| !s.is_empty())
        .map(rules::parse_size)
        .transpose()?;
    let target = copy::resolve(paths, &cfg, target.trim())?;
    Ok((cfg, target, sets, size))
}

fn text(r: Result<String>) -> Result<String, String> {
    r.map_err(|e| format!("{e:#}"))
}

pub(super) fn page(app: &mut App, ui: &mut egui::Ui) {
    rules_table(app, ui);
    ui.separator();
    add_form(app, ui);
}

fn rules_table(app: &mut App, ui: &mut egui::Ui) {
    let Some(snap) = &app.snap else {
        return;
    };
    let rules = snap.rules.clone();
    let last = snap.last_runs.clone();
    let mut run = None;
    let mut remove = None;
    egui::Grid::new("rules").striped(true).show(ui, |ui| {
        for h in ["rule", "every", "target", "sets", "size", "last run", ""] {
            ui.weak(h);
        }
        ui.end_row();
        for r in &rules {
            ui.monospace(&r.id);
            ui.label(rules::show_interval(r.interval));
            ui.label(r.target.name());
            ui.label(if r.sets.is_empty() {
                "all".to_string()
            } else {
                r.sets.join(",")
            });
            ui.label(r.size.map(crate::public::gb).unwrap_or_default());
            ui.label(
                last.get(&r.id)
                    .map_or_else(|| "never".to_string(), ToString::to_string),
            );
            ui.horizontal(|ui| {
                if ui.small_button("Run now").clicked() {
                    run = Some(r.id.clone());
                }
                if ui.small_button("Remove").clicked() {
                    remove = Some(r.id.clone());
                }
            });
            ui.end_row();
        }
    });
    if rules.is_empty() {
        ui.label("No copy rules. Copy rules are for drives other than the primary.");
    }
    if let Some(id) = run {
        app.run_command(Command::CopyRule(id));
    }
    if let Some(id) = remove {
        app.act(|p| copy::remove(p, &Store::new(p.queue.clone()), &id));
    }
}

fn add_form(app: &mut App, ui: &mut egui::Ui) {
    ui.strong("Add a rule");
    let drives = app.drives.clone();
    let mut find = false;
    let mut plan = false;
    let mut add = false;
    let f = &mut app.copy;
    egui::Grid::new("add-rule").num_columns(2).show(ui, |ui| {
        ui.label("Target (directory, drive id or label)");
        ui.horizontal(|ui| {
            ui.text_edit_singleline(&mut f.target);
            egui::ComboBox::from_id_salt("copy-drive")
                .selected_text("drives")
                .show_ui(ui, |ui| {
                    for (id, label) in &drives {
                        ui.selectable_value(&mut f.target, id.clone(), label);
                    }
                });
            find = ui.small_button("Find drives").clicked();
        });
        ui.end_row();
        ui.label("Every (H:MM:SS)");
        ui.add(egui::TextEdit::singleline(&mut f.every).hint_text("24:00:00"));
        ui.end_row();
        ui.label("Sets (empty = all)");
        ui.text_edit_singleline(&mut f.sets);
        ui.end_row();
        ui.label("Size (when not plugged in)");
        ui.add(egui::TextEdit::singleline(&mut f.size).hint_text("64G"));
        ui.end_row();
    });
    ui.horizontal(|ui| {
        plan = ui.button("Dry run").clicked();
        add = ui.button("Add rule").clicked();
    });
    if let Some(p) = &f.plan {
        match p {
            Ok(t) => ui.monospace(t.as_str()),
            Err(e) => ui.colored_label(ui.visuals().error_fg_color, e.as_str()),
        };
    }
    let (target, every, sets, size) = (
        f.target.clone(),
        f.every.clone(),
        f.sets.clone(),
        f.size.clone(),
    );
    if find {
        app.find_drives();
    }
    // Both resolve through udisks and the plan reads the whole primary: off the UI thread.
    if plan {
        app.copy.plan = None;
        app.spawn(move |paths| {
            Done::Plan(text(request(&paths, &target, &sets, &size).and_then(
                |(cfg, t, sets, size)| copy::plan_text(&cfg, &t, &sets, size),
            )))
        });
    } else if add {
        app.spawn(move |paths| {
            Done::Said(text(request(&paths, &target, &sets, &size).and_then(
                |(_, t, _, size)| {
                    let every = if every.trim().is_empty() {
                        "24:00:00"
                    } else {
                        every.trim()
                    };
                    copy::save_rule(&paths, &t, every, &tokens(&sets), size).map(|(_, msg)| msg)
                },
            )))
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_tokens() {
        assert_eq!(tokens(" a, b c,,"), ["a", "b", "c"]);
        assert_eq!(tokens(""), Vec::<String>::new());
    }
}
