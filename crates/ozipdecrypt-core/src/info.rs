use crate::detect::ContainerType;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartitionMeta {
    pub name: String,
    pub size: u64,
    pub is_encrypted: bool,
    pub checksum: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerInfo {
    pub container_type: ContainerType,
    pub file_size: u64,
    pub details: String,
    pub chipset: Option<String>,
    pub partitions: Vec<PartitionMeta>,
}
