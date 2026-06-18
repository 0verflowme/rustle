pub const AGENT_STREAM_INITIAL_WINDOW_BYTES: usize = 4 * 1024 * 1024;
pub const AGENT_STREAM_MAX_WINDOW_BYTES: usize = 24 * 1024 * 1024;
pub const AGENT_STREAM_RECEIVE_CREDIT_BATCH_BYTES: usize = 1024 * 1024;
pub const AGENT_STREAM_RECEIVE_CREDIT_MAX_BATCH_BYTES: usize = 1024 * 1024;
const AGENT_STREAM_WINDOW_GROWTH_FACTOR: usize = 2;
const AGENT_STREAM_RECEIVE_CREDIT_BATCH_DIVISOR: usize = 4;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentCreditWindow {
    current_window: usize,
    max_window: usize,
    pending_credit: usize,
    consumed_since_growth: usize,
}

impl AgentCreditWindow {
    pub fn new() -> Self {
        Self {
            current_window: AGENT_STREAM_INITIAL_WINDOW_BYTES,
            max_window: AGENT_STREAM_MAX_WINDOW_BYTES,
            pending_credit: 0,
            consumed_since_growth: 0,
        }
    }

    pub fn initial_credit() -> usize {
        AGENT_STREAM_INITIAL_WINDOW_BYTES
    }

    #[cfg(test)]
    pub fn current_window(&self) -> usize {
        self.current_window
    }

    pub fn record_consumed(&mut self, bytes: usize) -> Option<usize> {
        if bytes == 0 {
            return None;
        }

        self.pending_credit = self.pending_credit.saturating_add(bytes);
        self.consumed_since_growth = self.consumed_since_growth.saturating_add(bytes);

        let growth_credit = self.grow_if_sustained();
        let threshold = self.batch_threshold();
        if self.pending_credit < threshold && growth_credit == 0 {
            return None;
        }

        Some(std::mem::take(&mut self.pending_credit).saturating_add(growth_credit))
    }

    fn grow_if_sustained(&mut self) -> usize {
        let mut growth_credit = 0_usize;
        while self.current_window < self.max_window
            && self.consumed_since_growth >= self.current_window
        {
            self.consumed_since_growth -= self.current_window;
            let next = self
                .current_window
                .saturating_mul(AGENT_STREAM_WINDOW_GROWTH_FACTOR)
                .min(self.max_window);
            growth_credit = growth_credit.saturating_add(next.saturating_sub(self.current_window));
            self.current_window = next;
        }
        growth_credit
    }

    fn batch_threshold(&self) -> usize {
        (self.current_window / AGENT_STREAM_RECEIVE_CREDIT_BATCH_DIVISOR).clamp(
            AGENT_STREAM_RECEIVE_CREDIT_BATCH_BYTES,
            AGENT_STREAM_RECEIVE_CREDIT_MAX_BATCH_BYTES,
        )
    }
}

impl Default for AgentCreditWindow {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    #[kani::proof]
    #[kani::unwind(8)]
    fn record_consumed_keeps_window_within_configured_bounds() {
        let first: u32 = kani::any();
        let second: u32 = kani::any();
        kani::assume(first <= (AGENT_STREAM_MAX_WINDOW_BYTES * 2) as u32);
        kani::assume(second <= (AGENT_STREAM_MAX_WINDOW_BYTES * 2) as u32);

        let mut window = AgentCreditWindow::new();
        let _ = window.record_consumed(first as usize);
        assert!(window.current_window >= AGENT_STREAM_INITIAL_WINDOW_BYTES);
        assert!(window.current_window <= AGENT_STREAM_MAX_WINDOW_BYTES);

        let _ = window.record_consumed(second as usize);
        assert!(window.current_window >= AGENT_STREAM_INITIAL_WINDOW_BYTES);
        assert!(window.current_window <= AGENT_STREAM_MAX_WINDOW_BYTES);
        assert!(window.pending_credit <= (u32::MAX as usize));
    }

    #[kani::proof]
    fn zero_consumption_does_not_change_credit_window() {
        let mut window = AgentCreditWindow::new();
        let before = window.clone();

        assert!(window.record_consumed(0).is_none());
        assert_eq!(window, before);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_window_constants_match_live_rtt_targets() {
        assert_eq!(AGENT_STREAM_INITIAL_WINDOW_BYTES, 4 * 1024 * 1024);
        assert_eq!(AGENT_STREAM_MAX_WINDOW_BYTES, 24 * 1024 * 1024);
        assert_eq!(AGENT_STREAM_RECEIVE_CREDIT_BATCH_BYTES, 1024 * 1024);
        assert_eq!(AGENT_STREAM_RECEIVE_CREDIT_MAX_BATCH_BYTES, 1024 * 1024);
    }

    #[test]
    fn credit_window_batches_initial_credit_until_threshold() {
        let mut window = AgentCreditWindow::new();
        let chunk = AGENT_STREAM_RECEIVE_CREDIT_BATCH_BYTES / 4;

        for _ in 0..3 {
            assert_eq!(window.record_consumed(chunk), None);
        }
        assert_eq!(
            window.record_consumed(chunk),
            Some(AGENT_STREAM_RECEIVE_CREDIT_BATCH_BYTES)
        );
        assert_eq!(window.current_window(), AGENT_STREAM_INITIAL_WINDOW_BYTES);
    }

    #[test]
    fn credit_window_exact_threshold_flushes_and_resets_pending_credit() {
        let mut window = AgentCreditWindow::new();
        let threshold = window.batch_threshold();

        assert_eq!(threshold, AGENT_STREAM_RECEIVE_CREDIT_BATCH_BYTES);
        assert_eq!(window.record_consumed(threshold - 1), None);
        assert_eq!(window.pending_credit, threshold - 1);
        assert_eq!(window.consumed_since_growth, threshold - 1);

        assert_eq!(window.record_consumed(1), Some(threshold));
        assert_eq!(window.pending_credit, 0);
        assert_eq!(window.consumed_since_growth, threshold);
        assert_eq!(window.current_window(), AgentCreditWindow::initial_credit());
    }

    #[test]
    fn credit_window_initial_credit_matches_new_window_size() {
        let window = AgentCreditWindow::new();

        assert_eq!(
            AgentCreditWindow::initial_credit(),
            AGENT_STREAM_INITIAL_WINDOW_BYTES
        );
        assert_eq!(window.current_window, AgentCreditWindow::initial_credit());
        assert_eq!(window.max_window, AGENT_STREAM_MAX_WINDOW_BYTES);
        assert_eq!(window.pending_credit, 0);
        assert_eq!(window.consumed_since_growth, 0);
    }

    #[test]
    fn credit_window_grows_after_sustained_full_window_consumption() {
        let mut window = AgentCreditWindow::new();
        let mut current = AGENT_STREAM_INITIAL_WINDOW_BYTES;

        while current < AGENT_STREAM_MAX_WINDOW_BYTES {
            let next = current
                .saturating_mul(AGENT_STREAM_WINDOW_GROWTH_FACTOR)
                .min(AGENT_STREAM_MAX_WINDOW_BYTES);
            assert_eq!(window.record_consumed(current), Some(next));
            assert_eq!(window.current_window(), next);
            current = next;
        }
        assert_eq!(window.current_window(), AGENT_STREAM_MAX_WINDOW_BYTES);
    }

    #[test]
    fn credit_window_does_not_spend_growth_budget_at_max_window() {
        let mut window = AgentCreditWindow::new();

        assert_eq!(
            window.record_consumed(AGENT_STREAM_INITIAL_WINDOW_BYTES),
            Some(AGENT_STREAM_INITIAL_WINDOW_BYTES * 2)
        );
        assert_eq!(
            window.record_consumed(AGENT_STREAM_INITIAL_WINDOW_BYTES * 2),
            Some(AGENT_STREAM_INITIAL_WINDOW_BYTES * 4)
        );
        assert_eq!(
            window.record_consumed(AGENT_STREAM_INITIAL_WINDOW_BYTES * 4),
            Some(AGENT_STREAM_INITIAL_WINDOW_BYTES * 6)
        );
        assert_eq!(window.current_window(), AGENT_STREAM_MAX_WINDOW_BYTES);
        assert_eq!(window.consumed_since_growth, 0);

        assert_eq!(
            window.record_consumed(AGENT_STREAM_MAX_WINDOW_BYTES),
            Some(AGENT_STREAM_MAX_WINDOW_BYTES)
        );
        assert_eq!(window.current_window(), AGENT_STREAM_MAX_WINDOW_BYTES);
        assert_eq!(window.consumed_since_growth, AGENT_STREAM_MAX_WINDOW_BYTES);

        assert_eq!(window.record_consumed(1), None);
        assert_eq!(
            window.consumed_since_growth,
            AGENT_STREAM_MAX_WINDOW_BYTES + 1
        );
    }

    #[test]
    fn credit_window_caps_receive_credit_batch_threshold() {
        let mut window = AgentCreditWindow::new();

        assert_eq!(
            window.record_consumed(AGENT_STREAM_INITIAL_WINDOW_BYTES),
            Some(AGENT_STREAM_INITIAL_WINDOW_BYTES * 2)
        );
        assert_eq!(
            window.batch_threshold(),
            AGENT_STREAM_RECEIVE_CREDIT_MAX_BATCH_BYTES
        );

        assert_eq!(
            window.record_consumed(AGENT_STREAM_INITIAL_WINDOW_BYTES * 2),
            Some(AGENT_STREAM_INITIAL_WINDOW_BYTES * 4)
        );
        assert_eq!(
            window.batch_threshold(),
            AGENT_STREAM_RECEIVE_CREDIT_MAX_BATCH_BYTES
        );
    }

    #[test]
    fn credit_window_stays_bounded_after_repeated_large_consumption() {
        let mut window = AgentCreditWindow::new();

        assert!(window
            .record_consumed(AGENT_STREAM_MAX_WINDOW_BYTES * 4)
            .is_some());
        assert_eq!(window.current_window(), AGENT_STREAM_MAX_WINDOW_BYTES);
        assert!(window
            .record_consumed(AGENT_STREAM_MAX_WINDOW_BYTES * 4)
            .is_some());
        assert_eq!(window.current_window(), AGENT_STREAM_MAX_WINDOW_BYTES);
    }
}
