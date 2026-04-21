use std::cmp::Ordering;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum CheckState {
    Ok,
    Warn,
    Fail,
    Skip,
}

impl CheckState {
    fn severity(self) -> u8 {
        match self {
            CheckState::Skip => 0,
            CheckState::Ok => 1,
            CheckState::Warn => 2,
            CheckState::Fail => 3,
        }
    }
}

impl Ord for CheckState {
    fn cmp(&self, other: &Self) -> Ordering {
        self.severity().cmp(&other.severity())
    }
}

impl PartialOrd for CheckState {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_orders_fail_above_warn_above_ok_above_skip() {
        assert!(CheckState::Fail > CheckState::Warn);
        assert!(CheckState::Warn > CheckState::Ok);
        assert!(CheckState::Ok > CheckState::Skip);
    }

    #[test]
    fn worst_via_max_picks_fail() {
        let worst = [
            CheckState::Ok,
            CheckState::Skip,
            CheckState::Warn,
            CheckState::Ok,
            CheckState::Fail,
        ]
        .into_iter()
        .max()
        .unwrap();
        assert_eq!(worst, CheckState::Fail);
    }
}
