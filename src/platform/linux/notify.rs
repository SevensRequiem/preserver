use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use zbus::MatchRule;
use zbus::blocking::{Connection, MessageIterator};
use zbus::message::Type;
use zbus::zvariant::Value;

const NOTIFICATIONS: &str = "org.freedesktop.Notifications";
const PATH: &str = "/org/freedesktop/Notifications";
const RUN: &str = "run";

/// `replaces` 0 is a new notification; `expire_ms` -1 is the server's default and 0 never.
fn send(
    bus: &Connection,
    replaces: u32,
    urgent: bool,
    title: &str,
    body: &str,
    actions: &[&str],
    expire_ms: i32,
) -> zbus::Result<u32> {
    let hints = HashMap::from([("urgency", Value::U8(if urgent { 2 } else { 1 }))]);
    bus.call_method(
        Some(NOTIFICATIONS),
        PATH,
        Some(NOTIFICATIONS),
        "Notify",
        &(
            "Code archive",
            replaces,
            "folder-git",
            title,
            body,
            actions,
            hints,
            expire_ms,
        ),
    )?
    .body()
    .deserialize()
}

pub(crate) fn notify(urgent: bool, title: &str, body: &str) {
    let sent = Connection::session().and_then(|bus| send(&bus, 0, urgent, title, body, &[], -1));
    if let Err(e) = sent {
        tracing::debug!("notification: {e}");
    }
}

/// The overdue reminder with its "Back up now" button. One connection and one listener serve
/// every reminder, and a new one replaces the one still on screen.
#[derive(Clone)]
pub(crate) struct Reminder {
    bus: Connection,
    shown: Arc<AtomicU32>,
}

impl Reminder {
    /// `run` is called, on the listener thread, when the button of the current reminder is clicked.
    pub(crate) fn new(run: impl Fn() + Send + 'static) -> Result<Self> {
        let bus = Connection::session()?;
        let rule = MatchRule::builder()
            .msg_type(Type::Signal)
            .sender(NOTIFICATIONS)?
            .path(PATH)?
            .interface(NOTIFICATIONS)?
            .member("ActionInvoked")?
            .build();
        let signals = MessageIterator::for_match_rule(rule, &bus, None)?;
        let shown = Arc::new(AtomicU32::new(0));
        let current = Arc::clone(&shown);
        std::thread::spawn(move || {
            for signal in signals.map_while(Result::ok) {
                // Relaxed: the id is one independent value, written only by `show`.
                let id = current.load(Ordering::Relaxed);
                if id != 0
                    && signal
                        .body()
                        .deserialize::<(u32, &str)>()
                        .is_ok_and(|clicked| clicked == (id, RUN))
                {
                    run();
                }
            }
        });
        Ok(Self { bus, shown })
    }

    pub(crate) fn show(&self, body: &str) {
        // Relaxed: see the listener.
        let previous = self.shown.load(Ordering::Relaxed);
        let actions = [RUN, "Back up now"];
        match send(
            &self.bus,
            previous,
            false,
            "Personal backup overdue",
            body,
            &actions,
            0,
        ) {
            Ok(id) => self.shown.store(id, Ordering::Relaxed),
            Err(e) => tracing::warn!("reminder: {e}"),
        }
    }
}
