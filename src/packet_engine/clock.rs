use std::time::Instant as StdInstant;

use smoltcp::time::Instant as SmolInstant;

pub(crate) fn smol_now(started_at: StdInstant) -> SmolInstant {
    let millis = started_at.elapsed().as_millis().min(i64::MAX as u128) as i64;
    SmolInstant::from_millis(millis)
}
