#[derive(Debug)]
pub(crate) struct AdmissionCounter {
    max: usize,
    current: usize,
    dropped: u64,
    completed: u64,
}

impl AdmissionCounter {
    pub(crate) fn new(max: usize) -> Self {
        assert!(max > 0, "admission limit must be greater than zero");
        Self {
            max,
            current: 0,
            dropped: 0,
            completed: 0,
        }
    }

    pub(crate) fn max(&self) -> usize {
        self.max
    }

    #[cfg(test)]
    pub(crate) fn current(&self) -> usize {
        self.current
    }

    #[cfg(test)]
    pub(crate) fn dropped(&self) -> u64 {
        self.dropped
    }

    #[cfg(test)]
    pub(crate) fn completed(&self) -> u64 {
        self.completed
    }

    pub(crate) fn snapshot(&self) -> AdmissionSnapshot {
        AdmissionSnapshot {
            current: self.current,
            max: self.max,
        }
    }

    pub(crate) fn try_admit(&mut self) -> bool {
        if self.current >= self.max {
            self.dropped = self.dropped.saturating_add(1);
            return false;
        }

        self.current += 1;
        true
    }

    pub(crate) fn complete(&mut self) {
        if self.current > 0 {
            self.current -= 1;
            self.completed = self.completed.saturating_add(1);
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) struct AdmissionSnapshot {
    pub(crate) current: usize,
    pub(crate) max: usize,
}
