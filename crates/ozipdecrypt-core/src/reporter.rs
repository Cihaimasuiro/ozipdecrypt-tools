use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChecksumStatus {
    VerifiedFull,
    VerifiedHeadOnly,
    NoHashInManifest,
    Failed,
}

impl ChecksumStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            ChecksumStatus::VerifiedFull => "Verified full",
            ChecksumStatus::VerifiedHeadOnly => "Head checked only",
            ChecksumStatus::NoHashInManifest => "No checksum available",
            ChecksumStatus::Failed => "Failed",
        }
    }
}

#[derive(Debug, Clone)]
pub enum ProgressEvent {
    Started {
        total_items: usize,
        total_bytes: u64,
    },
    ItemStarted {
        name: String,
        size: u64,
    },
    Progress {
        bytes_done: u64,
        bytes_total: u64,
    },
    ItemDone {
        name: String,
        checksum: ChecksumStatus,
    },
    Warning(String),
    Finished,
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
