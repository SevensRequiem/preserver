pub(crate) mod client;
pub(crate) mod download;
mod hash;
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "git children are pointed at it by the mirror step, phase 3"
    )
)]
pub(crate) mod proxy;
#[cfg(test)]
pub(crate) mod testserver;
pub(crate) mod throttle;
