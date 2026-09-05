use std::{
    fs::{self, File},
    io::Write,
    path::Path,
};

use chrono::Utc;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager};
use tauri_plugin_dialog::DialogExt;
use zip::{CompressionMethod, ZipWriter, write::SimpleFileOptions};

use crate::error::AppError;

const DIAGNOSTIC_FORMAT_VERSION: u32 = 1;
const MAX_LOG_BYTES_PER_FILE: usize = 2 * 1024 * 1024;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiagnosticQueueItem {
    pub input_path: String,
    pub stage: String,
    pub error: Option<String>,
    pub output_path: Option<String>,
    pub entitlement_blocking_count: Option<usize>,
    pub entitlement_warning_count: Option<usize>,
    pub validation_passed: Option<bool>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SanitizedDiagnosticQueueItem {
    input_file: String,
    stage: String,
    error: Option<String>,
    output_file: Option<String>,
    entitlement_blocking_count: Option<usize>,
    entitlement_warning_count: Option<usize>,
    validation_passed: Option<bool>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DiagnosticMetadata {
    format_version: u32,
    generated_at_utc: String,
    application_version: String,
    operating_system: String,
    architecture: String,
    queue: Vec<SanitizedDiagnosticQueueItem>,
    privacy: DiagnosticPrivacyStatement,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DiagnosticPrivacyStatement {
    local_paths_reduced_to_file_names: bool,
    sensitive_log_lines_redacted: bool,
    credentials_intentionally_excluded: Vec<&'static str>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiagnosticBundleExportInfo {
    pub archive_path: String,
    pub included_log_files: usize,
    pub queue_items: usize,
}

fn basename(path: &str) -> String {
    Path::new(path)
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("unknown")
        .to_string()
}

fn looks_like_path_fragment(token: &str) -> bool {
    let trimmed = token.trim_matches(|ch: char| matches!(ch, '"' | '\'' | '(' | ')' | '[' | ']' | ',' | ';'));
    trimmed.starts_with('/')
        || trimmed.starts_with("file://")
        || trimmed.as_bytes().get(1) == Some(&b':') && trimmed.contains('\\')
}

fn sanitize_error(value: &str) -> String {
    let flattened = value.replace('\r', " ").replace('\n', " ");
    let mut result = flattened
        .split_whitespace()
        .map(|token| if looks_like_path_fragment(token) { "[PATH]" } else { token })
        .collect::<Vec<_>>()
        .join(" ");
    if result.len() > 4_096 {
        result.truncate(4_096);
        result.push_str("…");
    }
    result
}

fn is_sensitive_line(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    [
        "password",
        "passwd",
        "p12_password",
        "p12 password",
        "two-factor",
        "two factor",
        "2fa",
        "otp",
        "anisette",
        "auth token",
        "authorization:",
        "bearer ",
        "session token",
        "session_cookie",
        "x-apple-i-md",
        "x-apple-i-md-m",
        "x-apple-i-srl-no",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn sanitize_log(bytes: &[u8]) -> String {
    let start = bytes.len().saturating_sub(MAX_LOG_BYTES_PER_FILE);
    let text = String::from_utf8_lossy(&bytes[start..]);
    text.lines()
        .map(|line| {
            if is_sensitive_line(line) {
                "[REDACTED SENSITIVE LINE]"
            } else {
                line
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn zip_error(context: &str, error: impl std::fmt::Display) -> AppError {
    AppError::Filesystem(context.into(), error.to_string())
}

fn add_entry(
    writer: &mut ZipWriter<File>,
    name: &str,
    bytes: &[u8],
    options: SimpleFileOptions,
) -> Result<(), AppError> {
    writer
        .start_file(name, options)
        .map_err(|error| zip_error("Failed to create diagnostics ZIP entry", error))?;
    writer
        .write_all(bytes)
        .map_err(|error| zip_error("Failed to write diagnostics ZIP entry", error))
}

fn collect_logs(handle: &AppHandle) -> Vec<(String, Vec<u8>)> {
    let Ok(app_data_dir) = handle.path().app_data_dir() else {
        return Vec::new();
    };
    let log_dir = app_data_dir.join("logs");
    let Ok(entries) = fs::read_dir(log_dir) else {
        return Vec::new();
    };

    let mut files = entries
        .filter_map(Result::ok)
        .filter(|entry| entry.path().is_file())
        .collect::<Vec<_>>();
    files.sort_by_key(|entry| entry.metadata().and_then(|meta| meta.modified()).ok());
    files.reverse();
    files.truncate(2);

    files
        .into_iter()
        .filter_map(|entry| {
            let path = entry.path();
            let name = path.file_name()?.to_str()?.to_string();
            let bytes = fs::read(path).ok()?;
            Some((name, bytes))
        })
        .collect()
}

#[tauri::command]
pub async fn export_signing_diagnostics(
    handle: AppHandle,
    queue: Vec<DiagnosticQueueItem>,
) -> Result<Option<DiagnosticBundleExportInfo>, AppError> {
    let directory = handle
        .dialog()
        .file()
        .set_title("Choose a folder for the sanitized diagnostics bundle")
        .blocking_pick_folder();
    let Some(directory) = directory else {
        return Ok(None);
    };
    let directory = directory.into_path().map_err(|error| {
        AppError::Filesystem("Invalid diagnostics export directory".into(), error.to_string())
    })?;
    fs::create_dir_all(&directory).map_err(|error| {
        AppError::Filesystem(
            "Failed to create diagnostics output directory".into(),
            error.to_string(),
        )
    })?;

    let sanitized_queue = queue
        .iter()
        .map(|item| SanitizedDiagnosticQueueItem {
            input_file: basename(&item.input_path),
            stage: item.stage.clone(),
            error: item.error.as_deref().map(sanitize_error),
            output_file: item.output_path.as_deref().map(basename),
            entitlement_blocking_count: item.entitlement_blocking_count,
            entitlement_warning_count: item.entitlement_warning_count,
            validation_passed: item.validation_passed,
        })
        .collect::<Vec<_>>();

    let metadata = DiagnosticMetadata {
        format_version: DIAGNOSTIC_FORMAT_VERSION,
        generated_at_utc: Utc::now().to_rfc3339(),
        application_version: handle.package_info().version.to_string(),
        operating_system: std::env::consts::OS.to_string(),
        architecture: std::env::consts::ARCH.to_string(),
        queue: sanitized_queue,
        privacy: DiagnosticPrivacyStatement {
            local_paths_reduced_to_file_names: true,
            sensitive_log_lines_redacted: true,
            credentials_intentionally_excluded: vec![
                "Apple ID password",
                "2FA/OTP codes",
                "anisette headers/state",
                "developer authentication/session tokens",
                "PKCS#12 password/private key material",
            ],
        },
    };

    let metadata_bytes = serde_json::to_vec_pretty(&metadata)
        .map_err(|error| AppError::Misc(format!("Failed to serialize diagnostics metadata: {error}")))?;
    let logs = collect_logs(&handle);
    let archive_name = format!("iloader-diagnostics-{}.zip", Utc::now().format("%Y%m%d-%H%M%S"));
    let archive_path = directory.join(archive_name);
    let part_path = archive_path.with_extension("zip.part");

    let file = File::create(&part_path).map_err(|error| {
        AppError::Filesystem("Failed to create diagnostics ZIP".into(), error.to_string())
    })?;
    let mut writer = ZipWriter::new(file);
    let options = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Deflated)
        .unix_permissions(0o600);

    let result = (|| -> Result<(), AppError> {
        add_entry(&mut writer, "diagnostics.json", &metadata_bytes, options)?;
        add_entry(
            &mut writer,
            "README.txt",
            b"This bundle is intended for iloader troubleshooting. Local paths are reduced to file names and known credential-bearing log lines are redacted. Review the archive before sharing it.",
            options,
        )?;
        for (index, (name, bytes)) in logs.iter().enumerate() {
            let sanitized = sanitize_log(bytes);
            add_entry(
                &mut writer,
                &format!("logs/{:02}-{}", index + 1, basename(name)),
                sanitized.as_bytes(),
                options,
            )?;
        }
        writer
            .finish()
            .map_err(|error| zip_error("Failed to finalize diagnostics ZIP", error))?;
        Ok(())
    })();

    if let Err(error) = result {
        let _ = fs::remove_file(&part_path);
        return Err(error);
    }
    fs::rename(&part_path, &archive_path).map_err(|error| {
        let _ = fs::remove_file(&part_path);
        AppError::Filesystem(
            "Failed to publish diagnostics ZIP atomically".into(),
            error.to_string(),
        )
    })?;

    Ok(Some(DiagnosticBundleExportInfo {
        archive_path: archive_path.display().to_string(),
        included_log_files: logs.len(),
        queue_items: queue.len(),
    }))
}

#[cfg(test)]
mod tests {
    use super::{is_sensitive_line, sanitize_error, sanitize_log};

    #[test]
    fn redacts_credential_bearing_log_lines() {
        let input = b"normal line\nAuthorization: Bearer secret\nnext line";
        let sanitized = sanitize_log(input);
        assert!(sanitized.contains("normal line"));
        assert!(sanitized.contains("[REDACTED SENSITIVE LINE]"));
        assert!(!sanitized.contains("secret"));
        assert!(is_sensitive_line("p12 password: abc"));
    }

    #[test]
    fn removes_path_fragments_from_errors() {
        let sanitized = sanitize_error("failed C:\\Users\\alice\\secret.ipa at /Users/alice/temp/file");
        assert!(!sanitized.contains("alice"));
        assert_eq!(sanitized, "failed [PATH] at [PATH]");
    }
}
