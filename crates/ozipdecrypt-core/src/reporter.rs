#[derive(Debug, Clone)]
pub enum ProgressEvent {
    Started {
        item: String,
        total_bytes: u64,
    },
    Progress {
        item: String,
        done_bytes: u64,
        total_bytes: u64,
    },
    ItemDone {
        item: String,
        checksum_verified: bool,
    },
    Warning(String),
}

pub trait ProgressReporter: Send + Sync {
    fn on_event(&self, event: ProgressEvent);
    fn is_cancelled(&self) -> bool {
        false
    }
}

pub struct NoopReporter;
impl ProgressReporter for NoopReporter {
    fn on_event(&self, _event: ProgressEvent) {}
}
