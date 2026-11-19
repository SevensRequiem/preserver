mod job;
mod sched;
mod store;

use crate::cli::QueueAction;
use crate::config::Config;
use crate::paths::Paths;
use crate::{actions, public};
use anyhow::{Result, bail};
pub(crate) use job::{BlockReason, Job, JobKind, JobState, Lane, Progress, Target};
pub(crate) use sched::{Halt, Pass, Work, Worker, apply_control, halt_requested, reset, runnable};
use std::time::Duration;
pub(crate) use store::Store;

fn print(jobs: &[Job]) {
    println!(
        "{:<28} {:<24} {:>4} {:>11} {:>16}  job",
        "id", "state", "prio", "files", "MiB"
    );
    for j in jobs {
        let p = &j.progress;
        let what = match &j.kind {
            JobKind::Set { set } => format!("set {set}"),
            JobKind::Copy { target, .. } => format!("copy -> {}", target.name()),
            JobKind::Github { .. } => "github".to_string(),
            JobKind::Local => "local folders".to_string(),
        };
        println!(
            "{:<28} {:<24} {:>4} {:>5}/{:<5} {:>7}/{:<8}  {what}{}",
            j.id,
            j.state.to_string(),
            j.priority,
            p.files_done,
            p.files_total,
            p.bytes_done >> 20,
            p.bytes_total >> 20,
            j.error
                .as_deref()
                .map(|e| format!("  ({e})"))
                .unwrap_or_default()
        );
    }
}

/// `preserver queue …`. Only `run` needs the config; the controls just write `.ctl` files,
/// which the worker applies within a second (or on its next run).
pub(crate) fn cli(paths: &Paths, action: QueueAction) -> Result<()> {
    let store = Store::new(paths.queue.clone());
    let one = |id: Option<String>, all: bool| match (id, all) {
        (Some(id), false) => Ok(Some(id)),
        (None, true) => Ok(None),
        _ => bail!("give a job id or --all"),
    };
    match action {
        QueueAction::List { watch } => loop {
            print(&store.jobs()?);
            if !watch {
                return Ok(());
            }
            std::thread::sleep(Duration::from_secs(2));
            println!();
        },
        QueueAction::Show { id } => {
            println!("{}", serde_json::to_string_pretty(&store.job(&id)?)?);
            Ok(())
        }
        QueueAction::Pause { id, all } => {
            let id = one(id, all)?;
            store.edit_control(id.as_deref(), |c| c.pause = true)
        }
        QueueAction::Resume { id, all, drive } => {
            if let Some(d) = drive {
                let on = |j: &Job| {
                    j.drive.matches(&d)
                        || matches!(&j.kind, JobKind::Copy { target: Target::Drive { id, .. }, .. } if id.matches(&d))
                };
                for j in store.jobs()?.iter().filter(|j| on(j)) {
                    store.edit_control(Some(&j.id), |c| c.pause = false)?;
                }
                return Ok(());
            }
            let id = one(id, all)?;
            store.edit_control(id.as_deref(), |c| c.pause = false)
        }
        QueueAction::Cancel { id } => {
            store.job(&id)?;
            store.edit_control(Some(&id), |c| c.cancel = true)
        }
        QueueAction::Retry { id } => actions::retry(paths, &id),
        QueueAction::Prio { id, priority } => {
            store.job(&id)?;
            store.edit_control(Some(&id), |c| c.priority = Some(priority))
        }
        QueueAction::Run => {
            let cfg = Config::load(&paths.cfg)?;
            actions::mount(&cfg.primary_uuid);
            public::queue_run(paths, &cfg)
        }
    }
}
