mod job;
mod sched;
mod store;

use crate::cli::QueueAction;
use crate::config::Config;
use crate::paths::Paths;
use crate::public;
use anyhow::{Result, bail};
#[cfg(test)]
pub(crate) use job::BlockReason;
pub(crate) use job::{Job, JobKind, JobState, Lane};
pub(crate) use sched::{Pass, Worker, runnable};
use std::time::Duration;
pub(crate) use store::Store;

fn print(jobs: &[Job]) {
    println!(
        "{:<28} {:<24} {:>4} {:>11} {:>16}  job",
        "id", "state", "prio", "files", "MiB"
    );
    for j in jobs {
        let p = &j.progress;
        let JobKind::Set { set } = &j.kind;
        println!(
            "{:<28} {:<24} {:>4} {:>5}/{:<5} {:>7}/{:<8}  set {set}{}",
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
                for j in store.jobs()?.iter().filter(|j| j.drive.matches(&d)) {
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
        QueueAction::Retry { id } => {
            store.job(&id)?;
            store.edit_control(Some(&id), |c| c.retry += 1)
        }
        QueueAction::Prio { id, priority } => {
            store.job(&id)?;
            store.edit_control(Some(&id), |c| c.priority = Some(priority))
        }
        QueueAction::Run => public::queue_run(paths, &Config::load(&paths.cfg)?),
    }
}
