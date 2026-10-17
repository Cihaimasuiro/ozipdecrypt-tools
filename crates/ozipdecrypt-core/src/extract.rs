use crate::crypto::KeyConfig;
use crate::detect::{self, ContainerType};
use crate::error::{OzipError, Result};
use crate::ofp;
use crate::ofp_mtk;
use crate::ops;
use crate::ozip;
use crate::reporter::{ChecksumStatus, ProgressReporter};
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct ExtractRequest {
    pub input: PathBuf,
    pub out_dir: PathBuf,
    pub partitions: Option<Vec<String>>,
}

#[derive(Debug, Clone)]
pub struct ExtractItemSummary {
    pub name: String,
    pub size: u64,
    pub checksum: ChecksumStatus,
}

#[derive(Debug, Clone)]
pub struct ExtractSummary {
    pub container_type: ContainerType,
    pub items: Vec<ExtractItemSummary>,
    pub total_bytes: u64,
}

pub fn extract(
    req: &ExtractRequest,
    keys: &KeyConfig,
    reporter: &dyn ProgressReporter,
) -> Result<ExtractSummary> {
    let container_type = detect::detect_container(&req.input)
        .map_err(|_| OzipError::UnsupportedContainer(req.input.clone()))?;

    let single_partition = req
        .partitions
        .as_ref()
        .and_then(|parts| parts.first().cloned());

    let raw_results = match container_type {
        ContainerType::OfpQualcomm => ofp::extract_ofp_partition_with_reporter(
            &req.input,
            &req.out_dir,
            single_partition.as_deref(),
            keys,
            reporter,
        )
        .map_err(|e| OzipError::Other(e.to_string()))?,

        ContainerType::OfpMediaTek => ofp_mtk::extract_ofp_mtk_with_reporter(
            &req.input,
            &req.out_dir,
            single_partition.as_deref(),
            reporter,
        )
        .map_err(|e| OzipError::Other(e.to_string()))?,

        ContainerType::OnePlusOps => ops::extract_ops_with_reporter(
            &req.input,
            &req.out_dir,
            single_partition.as_deref(),
            reporter,
        )
        .map_err(|e| OzipError::Other(e.to_string()))?,

        ContainerType::Ozip => {
            if let Some(target) = single_partition {
                ozip::extract_ozip_partition_with_reporter(
                    &req.input,
                    &req.out_dir,
                    &target,
                    keys,
                    reporter,
                )
                .map_err(|e| OzipError::Other(e.to_string()))?
            } else {
                let out_zip = req.out_dir.join(format!(
                    "{}.zip",
                    req.input
                        .file_stem()
                        .and_then(|s| s.to_str())
                        .unwrap_or("firmware")
                ));
                if let Some(parent) = out_zip.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                ozip::decrypt_ozip_with_reporter(&req.input, &out_zip, keys, reporter)
                    .map_err(|e| OzipError::Other(e.to_string()))?;
                let size = out_zip.metadata().map(|m| m.len()).unwrap_or(0);
                vec![(
                    out_zip.file_name().unwrap().to_string_lossy().to_string(),
                    size,
                    ChecksumStatus::NoHashInManifest,
                )]
            }
        }

        ContainerType::StandardZip => {
            return Err(OzipError::UnsupportedContainer(req.input.clone()));
        }

        ContainerType::Unknown => {
            return Err(OzipError::UnsupportedContainer(req.input.clone()));
        }
    };

    let items: Vec<ExtractItemSummary> = raw_results
        .into_iter()
        .map(|(name, size, checksum)| ExtractItemSummary {
            name,
            size,
            checksum,
        })
        .collect();

    let total_bytes = items.iter().map(|it| it.size).sum();

    Ok(ExtractSummary {
        container_type,
        items,
        total_bytes,
    })
}
