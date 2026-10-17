use crate::detect::ContainerType;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationLevel {
    Verified,
    SyntheticOnly,
    Unverified,
}

impl VerificationLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            VerificationLevel::Verified => "Verified on real data",
            VerificationLevel::SyntheticOnly => "Synthetic only",
            VerificationLevel::Unverified => "Unverified",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartitionMeta {
    pub name: String,
    pub size: u64,
    pub is_encrypted: bool,
    pub has_checksum: bool,
    pub checksum: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerInfo {
    pub container_type: ContainerType,
    pub verification_level: VerificationLevel,
    pub file_size: u64,
    pub details: String,
    pub chipset: Option<String>,
    pub project: Option<String>,
    pub partitions: Vec<PartitionMeta>,
}
