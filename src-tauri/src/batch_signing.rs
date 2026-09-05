use std::{
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
};

use isideload::sideload::application::Application;
use serde::Serialize;
use tauri::{Emitter, State, Window};
use zip::{CompressionMethod, ZipWriter, write::SimpleFileOptions};

use crate::{
    error::AppError,
    sideload::{SideloaderGuard, SideloaderMutex},
    signing_validation::{SignedIpaValidation, validate_signed_ipa_path},
};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum BatchSigningStatus { Signed, Failed }

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
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchSigningReport { pub total: usize, pub signed: usize, pub failed: usize, pub output_directory: String, pub items: Vec<BatchSigningItemResult> }

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchSigningProgress { pub input_path: String, pub stage: String, pub app_name: Option<String>, pub bundle_identifier: Option<String>, pub output_path: Option<String>, pub error: Option<String> }

fn emit_progress(window: &Window, input_path: &str, stage: &str, app_name: Option<String>, bundle_identifier: Option<String>, output_path: Option<String>, error: Option<String>) {
    if let Err(error) = window.emit("batch_signing_progress", BatchSigningProgress { input_path: input_path.to_string(), stage: stage.to_string(), app_name, bundle_identifier, output_path, error }) {
        tracing::warn!("Failed to emit batch signing progress event: {}", error);
    }
}

fn zip_error(context: &str, err: impl std::fmt::Display) -> AppError { AppError::Filesystem(context.to_string(), err.to_string()) }

fn add_directory_to_zip(writer: &mut ZipWriter<File>, source_dir: &Path, archive_root: &str) -> Result<(), AppError> {
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated).unix_permissions(0o644);
    let dir_options = SimpleFileOptions::default().unix_permissions(0o755);
    fn walk(writer: &mut ZipWriter<File>, current: &Path, source_dir: &Path, archive_root: &str, options: SimpleFileOptions, dir_options: SimpleFileOptions) -> Result<(), AppError> {
        for entry in fs::read_dir(current).map_err(|e| zip_error("Failed to read signed app directory", e))? {
            let entry = entry.map_err(|e| zip_error("Failed to read signed app entry", e))?;
            let path = entry.path();
            let relative = path.strip_prefix(source_dir).map_err(|e| zip_error("Failed to build signed IPA path", e))?.to_string_lossy().replace('\\', "/");
            let archive_path = if relative.is_empty() { archive_root.to_string() } else { format!("{}/{}", archive_root.trim_end_matches('/'), relative) };
            if path.is_dir() {
                writer.add_directory(format!("{}/", archive_path), dir_options).map_err(|e| zip_error("Failed to add directory to signed IPA", e))?;
                walk(writer, &path, source_dir, archive_root, options, dir_options)?;
            } else if path.is_file() {
                writer.start_file(&archive_path, options).map_err(|e| zip_error("Failed to add file to signed IPA", e))?;
                let mut source = File::open(&path).map_err(|e| zip_error("Failed to open signed app file", e))?;
                let mut buffer = [0u8; 64 * 1024];
                loop { let read = source.read(&mut buffer).map_err(|e| zip_error("Failed to read signed app file", e))?; if read == 0 { break; } writer.write_all(&buffer[..read]).map_err(|e| zip_error("Failed to write signed IPA", e))?; }
            }
        }
        Ok(())
    }
    writer.add_directory(format!("{}/", archive_root.trim_end_matches('/')), dir_options).map_err(|e| zip_error("Failed to create signed IPA root", e))?;
    walk(writer, source_dir, source_dir, archive_root, options, dir_options)
}

fn package_signed_app(signed_app_path: &Path, output_path: &Path) -> Result<(), AppError> {
    let app_name = signed_app_path.file_name().ok_or_else(|| AppError::Misc("Signed app path has no file name".into()))?.to_string_lossy().to_string();
    if let Some(parent) = output_path.parent() { fs::create_dir_all(parent).map_err(|e| AppError::Filesystem("Failed to create output directory".into(), e.to_string()))?; }
    let part_path = output_path.with_extension("ipa.part");
    let file = File::create(&part_path).map_err(|e| AppError::Filesystem("Failed to create signed IPA".into(), e.to_string()))?;
    let mut writer = ZipWriter::new(file);
    if let Err(error) = add_directory_to_zip(&mut writer, signed_app_path, &format!("Payload/{}", app_name)).and_then(|_| writer.finish().map(|_| ()).map_err(|e| zip_error("Failed to finalize signed IPA", e))) {
        let _ = fs::remove_file(&part_path);
        return Err(error);
    }
    fs::rename(&part_path, output_path).map_err(|e| { let _ = fs::remove_file(&part_path); AppError::Filesystem("Failed to publish signed IPA atomically".into(), e.to_string()) })?;
    Ok(())
}

fn default_output_name(input: &Path) -> String { let stem = input.file_stem().and_then(|value| value.to_str()).filter(|value| !value.is_empty()).unwrap_or("signed-app"); format!("{}-signed.ipa", stem) }

#[tauri::command]
pub async fn batch_sign_ipas(window: Window, sideloader_state: State<'_, SideloaderMutex>, ipa_paths: Vec<String>, output_directory: String) -> Result<BatchSigningReport, AppError> {
    let output_dir = PathBuf::from(&output_directory);
    fs::create_dir_all(&output_dir).map_err(|e| AppError::Filesystem("Failed to create batch output directory".into(), e.to_string()))?;
    let mut sideloader = SideloaderGuard::take(&sideloader_state)?;
    let mut items = Vec::with_capacity(ipa_paths.len());

    for input in ipa_paths {
        emit_progress(&window, &input, "inspecting", None, None, None, None);
        let input_path = PathBuf::from(&input);
        let (app_name, bundle_identifier) = match Application::new(input_path.clone()) {
            Ok(app) => (app.main_app_name().ok(), app.main_bundle_id().ok()),
            Err(error) => { let message = format!("IPA preflight failed: {error:?}"); emit_progress(&window, &input, "failed", None, None, None, Some(message.clone())); items.push(BatchSigningItemResult { input_path: input, app_name: None, bundle_identifier: None, status: BatchSigningStatus::Failed, output_path: None, validation: None, error: Some(message) }); continue; }
        };
        emit_progress(&window, &input, "signing", app_name.clone(), bundle_identifier.clone(), None, None);
        match sideloader.get_mut().sign_app(input_path.clone(), None, false, None::<fn(f32) -> std::future::Ready<()>>).await {
            Ok((signed_app_path, _special)) => {
                let output_path = output_dir.join(default_output_name(&input_path));
                emit_progress(&window, &input, "packaging", app_name.clone(), bundle_identifier.clone(), Some(output_path.display().to_string()), None);
                let result = package_signed_app(&signed_app_path, &output_path).and_then(|_| {
                    emit_progress(&window, &input, "validating", app_name.clone(), bundle_identifier.clone(), Some(output_path.display().to_string()), None);
                    validate_signed_ipa_path(&output_path)
                });
                match result {
                    Ok(validation) if validation.valid => { let output = output_path.display().to_string(); emit_progress(&window, &input, "signed", app_name.clone(), bundle_identifier.clone(), Some(output.clone()), None); items.push(BatchSigningItemResult { input_path: input, app_name, bundle_identifier, status: BatchSigningStatus::Signed, output_path: Some(output), validation: Some(validation), error: None }); }
                    Ok(validation) => { let message = "Signed IPA failed structural validation; output was removed.".to_string(); let _ = fs::remove_file(&output_path); emit_progress(&window, &input, "failed", app_name.clone(), bundle_identifier.clone(), None, Some(message.clone())); items.push(BatchSigningItemResult { input_path: input, app_name, bundle_identifier, status: BatchSigningStatus::Failed, output_path: None, validation: Some(validation), error: Some(message) }); }
                    Err(error) => { let message = format!("Packaging/validation failed: {error}"); let _ = fs::remove_file(&output_path); emit_progress(&window, &input, "failed", app_name.clone(), bundle_identifier.clone(), None, Some(message.clone())); items.push(BatchSigningItemResult { input_path: input, app_name, bundle_identifier, status: BatchSigningStatus::Failed, output_path: None, validation: None, error: Some(message) }); }
                }
                if let Err(error) = fs::remove_dir_all(&signed_app_path) { tracing::warn!("Failed to clean signed app temp directory {}: {}", signed_app_path.display(), error); }
            }
            Err(error) => { let message = format!("Signing failed: {error:?}"); emit_progress(&window, &input, "failed", app_name.clone(), bundle_identifier.clone(), None, Some(message.clone())); items.push(BatchSigningItemResult { input_path: input, app_name, bundle_identifier, status: BatchSigningStatus::Failed, output_path: None, validation: None, error: Some(message) }); }
        }
    }
    let signed = items.iter().filter(|item| matches!(item.status, BatchSigningStatus::Signed)).count();
    let failed = items.len().saturating_sub(signed);
    Ok(BatchSigningReport { total: items.len(), signed, failed, output_directory, items })
}
