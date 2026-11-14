//! The Settings page: a form over every config.toml field. Save turns the difference between
//! the form and the file as loaded into `config_edit` edits, which keep comments and refuse
//! anything they cannot prove; the file is written once, or not at all.

use super::{App, Done};
use crate::config::{Config, Transport};
use crate::config_edit::{self, Edit, Place};
use crate::schedule::{Schedule, show_interval};
use eframe::egui;
use toml::{Table, Value};

const SCHEDULES: [(&str, &str); 3] = [
    ("personal", "GitHub"),
    ("local", "Local folders"),
    ("public", "Public sets"),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum When {
    Off,
    Every,
    Daily,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Sched {
    pub when: When,
    pub text: String,
}

impl Sched {
    fn of(s: Option<&Schedule>) -> Self {
        match s {
            None => Self {
                when: When::Off,
                text: String::new(),
            },
            Some(Schedule::Every(secs)) => Self {
                when: When::Every,
                text: show_interval(*secs),
            },
            Some(Schedule::Daily(t)) => Self {
                when: When::Daily,
                text: t.strftime("%H:%M").to_string(),
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Folder {
    /// Its index in the file as loaded; `None` for a row added in the form.
    pub orig: Option<usize>,
    pub name: String,
    pub path: String,
    pub origin: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Draft {
    pub owners: Vec<String>,
    pub primary: String,
    pub transport: Transport,
    pub bandwidth: u32,
    pub reserve: u8,
    pub local: Vec<Folder>,
    pub schedule: [Sched; 3],
}

impl Draft {
    pub(super) fn of(c: &Config) -> Self {
        Self {
            owners: c.owners.clone(),
            primary: c.primary_uuid.to_string(),
            transport: c.transport,
            bandwidth: c.bandwidth_mbit,
            reserve: c.reserve_percent,
            local: c
                .local
                .iter()
                .enumerate()
                .map(|(i, f)| Folder {
                    orig: Some(i),
                    name: f.name.clone(),
                    path: f.path.to_string_lossy().into_owned(),
                    origin: f.origin.clone().unwrap_or_default(),
                })
                .collect(),
            schedule: [
                Sched::of(c.schedule.personal.as_ref()),
                Sched::of(c.schedule.local.as_ref()),
                Sched::of(c.schedule.public.as_ref()),
            ],
        }
    }
}

fn s(v: &str) -> Value {
    Value::String(v.trim().to_string())
}

/// The edits that turn `old` into `new`. Removed folders go first, last index first, so the
/// indices of the remaining ones are known; then changed fields; then added folders. A schedule
/// whose text is not of the kind its radio button says is refused: config.toml tells the two
/// apart by the text alone, so "every 6:00" would save as daily at 06:00.
pub(super) fn edits(old: &Draft, new: &Draft) -> Result<Vec<Edit>, String> {
    let mut out = Vec::new();
    if old.owners != new.owners {
        let owners = new.owners.iter().map(|o| s(o)).collect();
        out.push(Edit::Set(Place::Top("owners"), Value::Array(owners)));
    }
    if old.primary != new.primary {
        out.push(Edit::Set(Place::Top("primary_uuid"), s(&new.primary)));
    }
    if old.transport != new.transport {
        out.push(Edit::Set(
            Place::Top("transport"),
            s(new.transport.as_str()),
        ));
    }
    if old.bandwidth != new.bandwidth {
        out.push(Edit::Set(
            Place::Top("bandwidth_mbit"),
            Value::Integer(i64::from(new.bandwidth)),
        ));
    }
    if old.reserve != new.reserve {
        out.push(Edit::Set(
            Place::Top("reserve_percent"),
            Value::Integer(i64::from(new.reserve)),
        ));
    }
    for (((key, name), o), n) in SCHEDULES.iter().zip(&old.schedule).zip(&new.schedule) {
        match n.when {
            When::Off if o.when != When::Off => out.push(Edit::Unset(Place::Schedule(key))),
            When::Off => {}
            _ if o != n => {
                match (n.when, n.text.trim().parse::<Schedule>()) {
                    (When::Every, Ok(Schedule::Every(_)))
                    | (When::Daily, Ok(Schedule::Daily(_))) => {}
                    (When::Every, _) => {
                        return Err(format!(
                            "{name}: give the interval as H:MM:SS, like 24:00:00"
                        ));
                    }
                    _ => return Err(format!("{name}: give the time of day as HH:MM, like 01:30")),
                }
                out.push(Edit::Set(Place::Schedule(key), s(&n.text)));
            }
            _ => {}
        }
    }
    let kept: Vec<usize> = new.local.iter().filter_map(|f| f.orig).collect();
    let removed: Vec<usize> = (0..old.local.len())
        .rev()
        .filter(|i| !kept.contains(i))
        .collect();
    out.extend(removed.iter().map(|i| Edit::RemoveLocal(*i)));
    for f in &new.local {
        let Some(o) = f.orig else {
            continue;
        };
        let at = o - removed.iter().filter(|r| **r < o).count();
        let was = &old.local[o];
        for (key, before, after) in [
            ("name", &was.name, &f.name),
            ("path", &was.path, &f.path),
            ("origin", &was.origin, &f.origin),
        ] {
            if before == after {
                continue;
            }
            out.push(if after.trim().is_empty() && key == "origin" {
                Edit::Unset(Place::Local(at, key))
            } else {
                Edit::Set(Place::Local(at, key), s(after))
            });
        }
    }
    for f in new.local.iter().filter(|f| f.orig.is_none()) {
        let mut t = Table::new();
        t.insert("name".into(), s(&f.name));
        t.insert("path".into(), s(&f.path));
        if !f.origin.trim().is_empty() {
            t.insert("origin".into(), s(&f.origin));
        }
        out.push(Edit::AddLocal(t));
    }
    Ok(out)
}

#[derive(Default)]
pub(super) struct Form {
    /// The file as last loaded, and the form over it.
    pub loaded: Option<Result<(Draft, Draft), String>>,
    /// The person saw that a new primary leaves the old archive where it is.
    confirm_primary: bool,
}

pub(super) fn page(app: &mut App, ui: &mut egui::Ui) {
    let Ok(paths) = &app.paths else {
        return;
    };
    if app.settings.loaded.is_none() {
        app.settings.loaded = Some(
            Config::load(&paths.cfg)
                .map(|c| (Draft::of(&c), Draft::of(&c)))
                .map_err(|e| format!("{e:#}")),
        );
        app.settings.confirm_primary = false;
    }
    let drives = app.drives.clone();
    let mut save = None;
    let form = &mut app.settings;
    let (old, d) = match &mut form.loaded {
        Some(Ok(pair)) => (&pair.0, &mut pair.1),
        Some(Err(e)) => {
            ui.colored_label(ui.visuals().error_fg_color, e.as_str());
            if ui.button("Reload").clicked() {
                form.loaded = None;
            }
            return;
        }
        None => return,
    };

    let find = fields(ui, d, old, &drives);
    folders(ui, d);

    ui.separator();
    if d.primary != old.primary {
        ui.checkbox(
            &mut form.confirm_primary,
            "Backups go to the new drive from now on; the old archive stays where it is",
        );
    }
    let changes = edits(old, d).unwrap_or_else(|e| {
        ui.colored_label(ui.visuals().error_fg_color, e);
        Vec::new()
    });
    let ready = !changes.is_empty() && (d.primary == old.primary || form.confirm_primary);
    let old = old.clone();
    ui.horizontal(|ui| {
        if ui.add_enabled(ready, egui::Button::new("Save")).clicked() {
            save = Some((changes, old));
        }
        if ui.button("Revert").clicked() {
            form.loaded = None;
        }
    });
    if find {
        app.find_drives();
    }
    if let Some((changes, old)) = save {
        app.spawn(move |paths| {
            // Another writer (the tray's transport menu, an editor) may have changed the file
            // since this page loaded it; saving over that would revert their change.
            let loaded = |now: &Config| {
                anyhow::ensure!(
                    Draft::of(now) == old,
                    "config.toml changed since this page was loaded; press Revert"
                );
                Ok(())
            };
            Done::Saved(
                config_edit::save(&paths, &changes, loaded)
                    .map(|()| "saved config.toml".to_string())
                    .map_err(|e| format!("{e:#}")),
            )
        });
    }
}

fn fields(ui: &mut egui::Ui, d: &mut Draft, old: &Draft, drives: &[(String, String)]) -> bool {
    let mut find = false;
    egui::Grid::new("settings").num_columns(2).show(ui, |ui| {
        ui.label("GitHub owners");
        ui.vertical(|ui| {
            let mut drop = None;
            for (i, o) in d.owners.iter_mut().enumerate() {
                ui.horizontal(|ui| {
                    ui.text_edit_singleline(o);
                    if ui.small_button("Remove").clicked() {
                        drop = Some(i);
                    }
                });
            }
            if let Some(i) = drop {
                d.owners.remove(i);
            }
            if ui.small_button("Add owner").clicked() {
                d.owners.push(String::new());
            }
        });
        ui.end_row();

        ui.label("GitHub transport");
        ui.horizontal(|ui| {
            for t in [Transport::Ssh, Transport::Https] {
                ui.radio_value(&mut d.transport, t, t.as_str());
            }
        });
        ui.end_row();

        ui.label("Bandwidth (Mbit/s, 0 = unlimited)");
        ui.add(
            egui::DragValue::new(&mut d.bandwidth)
                .range(0..=10_000)
                .clamp_existing_to_range(false),
        );
        ui.end_row();

        ui.label("Keep free on the drive (%)");
        ui.add(egui::DragValue::new(&mut d.reserve).range(0..=90));
        ui.end_row();

        ui.label("Primary drive");
        ui.horizontal(|ui| {
            egui::ComboBox::from_id_salt("primary")
                .selected_text(d.primary.as_str())
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut d.primary, old.primary.clone(), &old.primary);
                    for (id, label) in drives {
                        ui.selectable_value(&mut d.primary, id.clone(), label);
                    }
                });
            find = ui.small_button("Find drives").clicked();
        });
        ui.end_row();

        for (i, (_, name)) in SCHEDULES.iter().enumerate() {
            let sc = &mut d.schedule[i];
            ui.label(format!("Schedule: {name}"));
            ui.horizontal(|ui| {
                let before = sc.when;
                ui.radio_value(&mut sc.when, When::Off, "off");
                ui.radio_value(&mut sc.when, When::Every, "every H:MM:SS");
                ui.radio_value(&mut sc.when, When::Daily, "daily HH:MM");
                if sc.when != before {
                    sc.text = match sc.when {
                        When::Off => String::new(),
                        When::Every => "24:00:00".into(),
                        When::Daily => "01:30".into(),
                    };
                }
                if sc.when != When::Off {
                    ui.add(egui::TextEdit::singleline(&mut sc.text).desired_width(80.0));
                }
            });
            ui.end_row();
        }
    });

    find
}

fn folders(ui: &mut egui::Ui, d: &mut Draft) {
    ui.separator();
    ui.strong("Local folders");
    egui::Grid::new("local").num_columns(4).show(ui, |ui| {
        ui.weak("name");
        ui.weak("absolute path");
        ui.weak("origin (optional)");
        ui.end_row();
        let mut drop = None;
        for (i, f) in d.local.iter_mut().enumerate() {
            ui.add(egui::TextEdit::singleline(&mut f.name).desired_width(120.0));
            ui.add(egui::TextEdit::singleline(&mut f.path).desired_width(280.0));
            ui.add(egui::TextEdit::singleline(&mut f.origin).desired_width(90.0));
            if ui.small_button("Remove").clicked() {
                drop = Some(i);
            }
            ui.end_row();
        }
        if let Some(i) = drop {
            d.local.remove(i);
        }
    });
    if ui.small_button("Add folder").clicked() {
        d.local.push(Folder {
            orig: None,
            name: String::new(),
            path: String::new(),
            origin: String::new(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEXT: &str = "\
# mine
owners = [\"a\", \"b\"]
primary_uuid = \"0123abcd-2d54\"

[[local]]
name = \"docs\" # docs
path = \"/d\"

[[local]]
name = \"pics\"
path = \"/p\"

[[local]]
name = \"code\"
path = \"/c\"

[schedule]
personal = \"24:00:00\"
";

    fn apply_all(text: &str, edits: &[Edit]) -> String {
        edits.iter().fold(text.to_string(), |t, e| {
            config_edit::apply(&t, e).unwrap_or_else(|err| panic!("{e:?}: {err:#}"))
        })
    }

    #[test]
    fn unchanged_form_saves_nothing() {
        let d = Draft::of(&Config::parse(TEXT).unwrap());
        assert_eq!(edits(&d, &d.clone()), Ok(Vec::new()));
    }

    #[test]
    fn every_field_round_trips_through_the_file() {
        let old = Draft::of(&Config::parse(TEXT).unwrap());
        let mut new = old.clone();
        new.owners = vec!["a".into(), "c-d".into()];
        new.primary = "ABCD-1234".into();
        new.transport = Transport::Https;
        new.bandwidth = 0;
        new.reserve = 25;
        new.schedule[0] = Sched {
            when: When::Off,
            text: String::new(),
        };
        new.schedule[1] = Sched {
            when: When::Daily,
            text: "1:30".into(),
        };
        new.schedule[2] = Sched {
            when: When::Every,
            text: "6:00:00".into(),
        };
        // Drop "docs", rename "code" to the freed name, give "pics" an origin, add one.
        new.local.remove(0);
        new.local[1].name = "docs".into();
        new.local[0].origin = "google".into();
        new.local.push(Folder {
            orig: None,
            name: "music".into(),
            path: "/m".into(),
            origin: String::new(),
        });
        let text = apply_all(TEXT, &edits(&old, &new).unwrap());
        assert!(text.starts_with("# mine\n"), "{text}");
        let got = Draft::of(&Config::parse(&text).unwrap());
        let mut want = new.clone();
        want.schedule[1].text = "01:30".into();
        for (i, f) in want.local.iter_mut().enumerate() {
            f.orig = Some(i);
        }
        assert_eq!(got, want);
    }

    #[test]
    fn a_schedule_of_the_other_kind_is_refused() {
        let old = Draft::of(&Config::parse(TEXT).unwrap());
        for (when, text) in [
            (When::Every, "6:00"),
            (When::Daily, "1:00:00"),
            (When::Daily, "x"),
        ] {
            let mut new = old.clone();
            new.schedule[1] = Sched {
                when,
                text: text.into(),
            };
            assert!(edits(&old, &new).is_err(), "{when:?} {text}");
        }
    }

    #[test]
    fn a_bad_field_is_refused_by_the_edit() {
        let old = Draft::of(&Config::parse(TEXT).unwrap());
        let mut new = old.clone();
        new.local[0].path = "relative".into();
        let e = edits(&old, &new).unwrap();
        assert!(config_edit::apply(TEXT, &e[0]).is_err());
    }
}
