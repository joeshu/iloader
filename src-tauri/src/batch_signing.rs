use std::{
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
    time::Instant,
};

use isideload::sideload::application::Application;
use serde::Serialize;
use tauri::{Emitter, State, Window};
use zip::{CompressionMethod, ZipWriter, write::SimpleFileOptions};

use crate::{
    error::AppError,
    preflight_cache::invalidate_team,
    sideload::{SideloaderGuard, SideloaderMutex},
    signing_report::write_signing_report,
    signing_validation::{SignedIpaValidation, validate_signed_ipa_path},
};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum BatchSigningStatus {
    Signed,
    Failed,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchSigningStageTimings {
    pub inspection_ms: u64,
    pub signing_ms: u64,
    pub packaging_ms: u64,
    pub validation_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchSigningItemResult {
    pub input_path: String,
    pub app_name: Option<String>,
    pub bundle_identifier: Option<String>,
    pub status: BatchSigningStatus,
    pub output_path: Option<String>,
    pub validation: Option<SignedIpaValidation>,
    pub error: Option<String>,
    pub duration_ms: u64,
    pub stage_timings: BatchSigningStageTimings,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchSigningReport {
    pub total: usize,
    pub signed: usize,
    pub failed: usize,
    pub output_directory: String,
    pub batch_duration_ms: u64,
    pub report_path: Option<String>,
    pub report_error: Option<String>,
    pub items: Vec<BatchSigningItemResult>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchSigningProgress {
    pub input_path: String,
    pub stage: String,
    pub app_name: Option<String>,
    pub bundle_identifier: Option<String>,
    pub output_path: Option<String>,
    pub error: Option<String>,
}

fn elapsed_ms(started: Instant) -> u64 {
    started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
}

fn emit_progress(
    window: &Window,
    input_path: &str,
    stage: &str,
    app_name: Option<String>,
    bundle_identifier: Option<String>,
    output_path: Option<String>,
    error: Option<String>,
) {
    if let Err(error) = window.emit(
        "batch_signing_progress",
        BatchSigningProgress {
            input_path: input_path.to_string(),
            stage: stage.to_string(),
            app_name,
            bundle_identifier,
            output_path,
            error,
        },
    ) {
        tracing::warn!("Failed to emit batch signing progress event: {}", error);
    }
}

fn zip_error(context: &str, error: impl std::fmt::Display) -> AppError {
    AppError::Filesystem(context.to_string(), error.to_string())
}

fn add_directory_to_zip(
    writer: &mut ZipWriter<File>,
    source_dir: &Path,
    archive_root: &str,
) -> Result<(), AppError> {
    let file_options = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Deflated)
        .unix_permissions(0o644);
    let directory_options = SimpleFileOptions::default().unix_permissions(0o755);

    fn walk(
        writer: &mut ZipWriter<File>,
        current: &Path,
        source_dir: &Path,
        archive_root: &str,
        file_options: SimpleFileOptions,
        directory_options: SimpleFileOptions,
    ) -> Result<(), AppError> {
        for entry in fs::read_dir(current)
            .map_err(|error| zip_error("Failed to read signed app directory", error))?
        {
            let entry = entry.map_err(|error| zip_error("Failed to read signed app entry", error))?;
            let path = entry.path();
            let relative = path
                .strip_prefix(source_dir)
                .map_err(|error| zip_error("Failed to build signed IPA path", error))?
                .to_string_lossy()
                .replace('\\', "/");
            let archive_path = if relative.is_empty() {
                archive_root.to_string()
            } else {
                format!("{}/{}", archive_root.trim_end_matches('/'), relative)
            };

            if path.is_dir() {
                writer
                    .add_directory(format!("{archive_path}/"), directory_options)
                    .map_err(|error| zip_error("Failed to add directory to signed IPA", error))?;
                walk(
                    writer,
                    &path,
                    source_dir,
                    archive_root,
                    file_options,
                    directory_options,
                )?;
            } else if path.is_file() {
                writer
                    .start_file(&archive_path, file_options)
                    .map_err(|error| zip_error("Failed to add file to signed IPA", error))?;
                let mut source = File::open(&path)
                    .map_err(|error| zip_error("Failed to open signed app file", error))?;
                let mut buffer = [0_u8; 64 * 1024];
                loop {
                    let read = source
                        .read(&mut buffer)
                        .map_err(|error| zip_error("Failed to read signed app file", error))?;
                    if read == 0 {
                        break;
                    }
                    writer
                        .write_all(&buffer[..read])
                        .map_err(|error| zip_error("Failed to write signed IPA", error))?;
                }
            }
        }
        Ok(())
    }

    writer
        .add_directory(
            format!("{}/", archive_root.trim_end_matches('/')),
            directory_options,
        )
        .map_err(|error| zip_error("Failed to create signed IPA root", error))?;
    walk(
        writer,
        source_dir,
        source_dir,
        archive_root,
        file_options,
        directory_options,
    )
}

fn package_signed_app(signed_app_path: &Path, output_path: &Path) -> Result<(), AppError> {
    let app_name = signed_app_path
        .file_name()
        .ok_or_else(|| AppError::Misc("Signed app path has no file name".into()))?
        .to_string_lossy()
        .to_string();

    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent).map_err(|error| {
            AppError::Filesystem("Failed to create output directory".into(), error.to_string())
        })?;
    }

    let part_path = output_path.with_extension("ipa.part");
    let _ = fs::remove_file(&part_path);
    let file = File::create(&part_path).map_err(|error| {
        AppError::Filesystem("Failed to create signed IPA".into(), error.to_string())
    })?;
    let mut writer = ZipWriter::new(file);

    let write_result = add_directory_to_zip(
        &mut writer,
        signed_app_path,
        &format!("Payload/{app_name}"),
    )
    .and_then(|_| {
        writer
            .finish()
            .map(|_| ())
            .map_err(|error| zip_error("Failed to finalize signed IPA", error))
    });

    if let Err(error) = write_result {
        let _ = fs::remove_file(&part_path);
        return Err(error);
    }

    fs::rename(&part_path, output_path).map_err(|error| {
        let _ = fs::remove_file(&part_path);
        AppError::Filesystem(
            "Failed to publish signed IPA atomically".into(),
            error.to_string(),
        )
    })
}

fn output_stem(input: &Path) -> String {
    input
        .file_stem()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty())
        .unwrap_or("signed-app")
        .to_string()
}

fn unique_output_path(output_dir: &Path, input: &Path) -> PathBuf {
    let stem = output_stem(input);
    let first = output_dir.join(format!("{stem}-signed.ipa"));
    if !first.exists() {
        return first;
    }

    for index in 2..=10_000 {
        let candidate = output_dir.join(format!("{stem}-signed-{index}.ipa"));
        if !candidate.exists() {
            return candidate;
        }
    }

    output_dir.join(format!("{stem}-signed-overflow.ipa"))
}

fn failed_item(
    input_path: String,
    app_name: Option<String>,
    bundle_identifier: Option<String>,
    validation: Option<SignedIpaValidation>,
    error: String,
    duration_ms: u64,
    stage_timings: BatchSigningStageTimings,
) -> BatchSigningItemResult {
    BatchSigningItemResult {
        input_path,
        app_name,
        bundle_identifier,
        status: BatchSigningStatus::Failed,
        output_path: None,
        validation,
        error: Some(error),
        duration_ms,
        stage_timings,
    }
}

#[tauri::command]
pub async fn batch_sign_ipas(
    window: Window,
    sideloader_state: State<'_, SideloaderMutex>,
    ipa_paths: Vec<String>,
    output_directory: String,
) -> Result<BatchSigningReport, AppError> {
    let batch_started = Instant::now();
    let output_dir = PathBuf::from(&output_directory);
    fs::create_dir_all(&output_dir).map_err(|error| {
        AppError::Filesystem(
            "Failed to create batch output directory".into(),
            error.to_string(),
        )
    })?;

    let mut sideloader = SideloaderGuard::take(&sideloader_state)?;
    let account_scope = sideloader.get_mut().get_email().to_string();
    let team_id = sideloader.get_mut().get_team().await?.team_id;
    let mut items = Vec::with_capacity(ipa_paths.len());

    for input in ipa_paths {
        let item_started = Instant::now();
        let mut timings = BatchSigningStageTimings::default();
        emit_progress(&window, &input, "inspecting", None, None, None, None);
        let input_path = PathBuf::from(&input);

        let inspection_started = Instant::now();
        let inspection = Application::new(input_path.clone());
        timings.inspection_ms = elapsed_ms(inspection_started);
        let (app_name, bundle_identifier) = match inspection {
            Ok(application) => (
                application.main_app_name().ok(),
                application.main_bundle_id().ok(),
            ),
            Err(error) => {
                let message = format!("IPA inspection failed: {error:?}");
                emit_progress(
                    &window,
                    &input,
                    "failed",
                    None,
                    None,
                    None,
                    Some(message.clone()),
                );
                items.push(failed_item(
                    input,
                    None,
                    None,
                    None,
                    message,
                    elapsed_ms(item_started),
                    timings,
                ));
                continue;
            }
        };

        emit_progress(
            &window,
            &input,
            "signing",
            app_name.clone(),
            bundle_identifier.clone(),
            None,
            None,
        );

        let signing_started = Instant::now();
        let signing_result = sideloader
            .get_mut()
            .sign_app(
                input_path.clone(),
                None,
                false,
                None::<fn(f32) -> std::future::Ready<()>>,
            )
            .await;
        timings.signing_ms = elapsed_ms(signing_started);

        invalidate_team(&account_scope, &team_id);

        let (signed_app_path, _special) = match signing_result {
            Ok(result) => result,
            Err(error) => {
                let message = format!("Signing failed: {error:?}");
                emit_progress(
                    &window,
                    &input,
                    "failed",
                    app_name.clone(),
                    bundle_identifier.clone(),
                    None,
                    Some(message.clone()),
                );
                items.push(failed_item(
                    input,
                    app_name,
                    bundle_identifier,
                    None,
                    message,
                    elapsed_ms(item_started),
                    timings,
                ));
                continue;
            }
        };

        let output_path = unique_output_path(&output_dir, &input_path);
        let output_path_string = output_path.display().to_string();
        emit_progress(
            &window,
            &input,
            "packaging",
            app_name.clone(),
            bundle_identifier.clone(),
            Some(output_path_string.clone()),
            None,
        );

        let packaging_started = Instant::now();
        let packaging_result = package_signed_app(&signed_app_path, &output_path);
        timings.packaging_ms = elapsed_ms(packaging_started);

        if let Err(error) = packaging_result {
            let message = format!("Packaging failed: {error}");
            let _ = fs::remove_file(&output_path);
            emit_progress(
                &window,
                &input,
                "failed",
                app_name.clone(),
                bundle_identifier.clone(),
                None,
                Some(message.clone()),
            );
            items.push(failed_item(
                input,
                app_name,
                bundle_identifier,
                None,
                message,
                elapsed_ms(item_started),
                timings,
            ));
            let _ = fs::remove_dir_all(&signed_app_path);
            continue;
        }

        emit_progress(
            &window,
            &input,
            "validating",
            app_name.clone(),
            bundle_identifier.clone(),
            Some(output_path_string.clone()),
            None,
        );
        let validation_started = Instant::now();
        let validation_result = validate_signed_ipa_path(&output_path);
        timings.validation_ms = elapsed_ms(validation_started);

        match validation_result {
            Ok(validation) if validation.valid => {
                emit_progress(
                    &window,
                    &input,
                    "signed",
                    app_name.clone(),
                    bundle_identifier.clone(),
                    Some(output_path_string.clone()),
                    None,
                );
                items.push(BatchSigningItemResult {
                    input_path: input,
                    app_name,
                    bundle_identifier,
                    status: BatchSigningStatus::Signed,
                    output_path: Some(output_path_string),
                    validation: Some(validation),
                    error: None,
                    duration_ms: elapsed_ms(item_started),
                    stage_timings: timings,
                });
            }
            Ok(validation) => {
                let message = "Signed IPA failed structural validation; output was removed.".to_string();
                let _ = fs::remove_file(&output_path);
                emit_progress(
                    &window,
                    &input,
                    "failed",
                    app_name.clone(),
                    bundle_identifier.clone(),
                    None,
                    Some(message.clone()),
                );
                items.push(failed_item(
                    input,
                    app_name,
                    bundle_identifier,
                    Some(validation),
                    message,
                    elapsed_ms(item_started),
                    timings,
                ));
            }
            Err(error) => {
                let message = format!("Validation failed: {error}");
                let _ = fs::remove_file(&output_path);
                emit_progress(
                    &window,
                    &input,
                    "failed",
                    app_name.clone(),
                    bundle_identifier.clone(),
                    None,
                    Some(message.clone()),
                );
                items.push(failed_item(
                    input,
                    app_name,
                    bundle_identifier,
                    None,
                    message,
                    elapsed_ms(item_started),
                    timings,
                ));
            }
        }

        if let Err(error) = fs::remove_dir_all(&signed_app_path) {
            tracing::warn!(
                "Failed to clean signed app temp directory {}: {}",
                signed_app_path.display(),
                error
            );
        }
    }

    let signed = items
        .iter()
        .filter(|item| matches!(item.status, BatchSigningStatus::Signed))
        .count();
    let failed = items.len().saturating_sub(signed);
    let batch_duration_ms = elapsed_ms(batch_started);

    let (report_path, report_error) = match write_signing_report(
        &output_dir,
        &team_id,
        &items,
        batch_duration_ms,
    ) {
        Ok(path) => (Some(path.display().to_string()), None),
        Err(error) => {
            tracing::warn!("Failed to write signing-report.json: {}", error);
            (
                None,
                Some("Signed outputs completed, but signing-report.json could not be written.".to_string()),
            )
        }
    };

    Ok(BatchSigningReport {
        total: items.len(),
        signed,
        failed,
        output_directory,
        batch_duration_ms,
        report_path,
        report_error,
        items,
    })
}
