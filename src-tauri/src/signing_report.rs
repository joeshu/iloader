use std::{
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
};

use chrono::Utc;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{
    batch_signing::{BatchSigningItemResult, BatchSigningStageTimings, BatchSigningStatus},
    error::AppError,
};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct SigningReportItem {
    input_file: String,
    app_name: Option<String>,
    bundle_identifier: Option<String>,
    status: String,
    output_file: Option<String>,
    output_sha256: Option<String>,
    duration_ms: u64,
    stage_timings: BatchSigningStageTimings,
    validation_passed: Option<bool>,
    extension_count: Option<usize>,
    extension_profiles: Option<usize>,
    error_summary: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
struct SigningReportStageTotals {
    inspection_ms: u64,
    signing_ms: u64,
    packaging_ms: u64,
    validation_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct SigningReportConcurrency {
    signing: usize,
    post_process: usize,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct SigningReportDocument {
    format_version: u32,
    generated_at_utc: String,
    team_id: String,
    total: usize,
    signed: usize,
    failed: usize,
    batch_duration_ms: u64,
    concurrency: SigningReportConcurrency,
    stage_totals: SigningReportStageTotals,
    items: Vec<SigningReportItem>,
}

fn basename(path: &str) -> String {
    path.replace('\\', "/")
        .rsplit('/')
        .next()
        .filter(|value| !value.is_empty())
        .unwrap_or("unknown")
        .to_string()
}

fn sha256_file(path: &Path) -> Result<String, AppError> {
    let mut file = File::open(path).map_err(|error| {
        AppError::Filesystem(
            "Failed to open signed IPA for report checksum".into(),
            error.to_string(),
        )
    })?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(|error| {
            AppError::Filesystem(
                "Failed to read signed IPA for report checksum".into(),
                error.to_string(),
            )
        })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn status_name(status: &BatchSigningStatus) -> &'static str {
    match status {
        BatchSigningStatus::Signed => "signed",
        BatchSigningStatus::Failed => "failed",
    }
}

fn generic_error_summary(item: &BatchSigningItemResult) -> Option<String> {
    if item.error.is_none() {
        return None;
    }
    Some(match item.status {
        BatchSigningStatus::Signed => "Completed with a non-fatal warning".to_string(),
        BatchSigningStatus::Failed => {
            "Signing pipeline failed; inspect sanitized diagnostics for details".to_string()
        }
    })
}

fn saturating_add(total: &mut u64, value: u64) {
    *total = total.saturating_add(value);
}

pub fn write_signing_report(
    output_dir: &Path,
    team_id: &str,
    items: &[BatchSigningItemResult],
    batch_duration_ms: u64,
    signing_concurrency: usize,
    post_process_concurrency: usize,
) -> Result<PathBuf, AppError> {
    let report_path = output_dir.join("signing-report.json");
    let part_path = output_dir.join("signing-report.json.part");
    let _ = fs::remove_file(&part_path);

    let mut stage_totals = SigningReportStageTotals::default();
    let report_items = items
        .iter()
        .map(|item| {
            saturating_add(&mut stage_totals.inspection_ms, item.stage_timings.inspection_ms);
            saturating_add(&mut stage_totals.signing_ms, item.stage_timings.signing_ms);
            saturating_add(&mut stage_totals.packaging_ms, item.stage_timings.packaging_ms);
            saturating_add(&mut stage_totals.validation_ms, item.stage_timings.validation_ms);

            let output_sha256 = item
                .output_path
                .as_deref()
                .map(Path::new)
                .filter(|path| path.is_file())
                .map(sha256_file)
                .transpose()?;
            let validation = item.validation.as_ref();
            Ok(SigningReportItem {
                input_file: basename(&item.input_path),
                app_name: item.app_name.clone(),
                bundle_identifier: item.bundle_identifier.clone(),
                status: status_name(&item.status).to_string(),
                output_file: item.output_path.as_deref().map(basename),
                output_sha256,
                duration_ms: item.duration_ms,
                stage_timings: item.stage_timings.clone(),
                validation_passed: validation.map(|value| value.valid),
                extension_count: validation.map(|value| value.extension_count),
                extension_profiles: validation.map(|value| value.extension_profiles),
                error_summary: generic_error_summary(item),
            })
        })
        .collect::<Result<Vec<_>, AppError>>()?;

    let signed = items
        .iter()
        .filter(|item| matches!(item.status, BatchSigningStatus::Signed))
        .count();
    let document = SigningReportDocument {
        format_version: 1,
        generated_at_utc: Utc::now().to_rfc3339(),
        team_id: team_id.to_string(),
        total: items.len(),
        signed,
        failed: items.len().saturating_sub(signed),
        batch_duration_ms,
        concurrency: SigningReportConcurrency {
            signing: signing_concurrency,
            post_process: post_process_concurrency,
        },
        stage_totals,
        items: report_items,
    };

    let bytes = serde_json::to_vec_pretty(&document)
        .map_err(|error| AppError::Misc(format!("Failed to serialize signing report: {error}")))?;
    let mut file = File::create(&part_path).map_err(|error| {
        AppError::Filesystem("Failed to create signing report".into(), error.to_string())
    })?;
    file.write_all(&bytes).map_err(|error| {
        AppError::Filesystem("Failed to write signing report".into(), error.to_string())
    })?;
    file.sync_all().map_err(|error| {
        AppError::Filesystem("Failed to flush signing report".into(), error.to_string())
    })?;
    drop(file);

    if report_path.exists() {
        fs::remove_file(&report_path).map_err(|error| {
            let _ = fs::remove_file(&part_path);
            AppError::Filesystem("Failed to replace signing report".into(), error.to_string())
        })?;
    }
    fs::rename(&part_path, &report_path).map_err(|error| {
        let _ = fs::remove_file(&part_path);
        AppError::Filesystem("Failed to publish signing report".into(), error.to_string())
    })?;

    Ok(report_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basename_never_leaks_parent_directories() {
        assert_eq!(basename(r"C:\Users\Alice\secret\Demo.ipa"), "Demo.ipa");
        assert_eq!(basename("/home/alice/private/Demo.ipa"), "Demo.ipa");
    }

    #[test]
    fn stage_total_addition_saturates_instead_of_wrapping() {
        let mut total = u64::MAX - 1;
        saturating_add(&mut total, 10);
        assert_eq!(total, u64::MAX);
    }
}
