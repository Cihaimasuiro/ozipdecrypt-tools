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

    // Partition selection semantics:
    // None -> extract everything
    // Some([]) -> error (user unselected all items)
    // Some([p1, p2, ...]) -> extract all matching partitions
    let target_partitions = match &req.partitions {
        Some(list) => {
            if list.is_empty() {
                return Err(OzipError::Other(
                    "No partitions selected for extraction".to_string(),
                ));
            }
            Some(list.as_slice())
        }
        None => None,
    };

    let raw_results = match container_type {
        ContainerType::OfpQualcomm => ofp::extract_ofp_partitions_with_reporter(
            &req.input,
            &req.out_dir,
            target_partitions,
            keys,
            reporter,
        )
        .map_err(to_ozip_error)?,

        ContainerType::OfpMediaTek => ofp_mtk::extract_ofp_mtk_partitions_with_reporter(
            &req.input,
            &req.out_dir,
            target_partitions,
            reporter,
        )
        .map_err(to_ozip_error)?,

        ContainerType::OnePlusOps => ops::extract_ops_partitions_with_reporter(
            &req.input,
            &req.out_dir,
            target_partitions,
            reporter,
        )
        .map_err(to_ozip_error)?,

        ContainerType::Ozip => {
            if let Some(targets) = target_partitions {
                ozip::extract_ozip_partitions_with_reporter(
                    &req.input,
                    &req.out_dir,
                    targets,
                    keys,
                    reporter,
                )
                .map_err(to_ozip_error)?
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
                    .map_err(to_ozip_error)?;
                let size = out_zip.metadata().map(|m| m.len()).unwrap_or(0);
                vec![(
                    out_zip.file_name().unwrap().to_string_lossy().to_string(),
                    size,
                    ChecksumStatus::NoHashInManifest,
                )]
            }
        }

        ContainerType::StandardZip | ContainerType::Unknown => {
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

fn to_ozip_error(e: anyhow::Error) -> OzipError {
    match e.downcast::<OzipError>() {
        Ok(err) => err,
        Err(other) => {
            if let Some(io_err) = other.downcast_ref::<std::io::Error>() {
                OzipError::Io(std::io::Error::new(io_err.kind(), io_err.to_string()))
            } else {
                OzipError::Other(other.to_string())
            }
        }
    }
}
