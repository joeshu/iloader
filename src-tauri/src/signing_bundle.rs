use std::{
    fs::File,
    io::Write,
    path::{Path, PathBuf},
};

use isideload::{
    dev::app_ids::AppIdsApi,
    sideload::application::Application,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use tauri::{AppHandle, State};
use tauri_plugin_dialog::DialogExt;
use zip::{CompressionMethod, ZipWriter, write::SimpleFileOptions};

use crate::{
    error::AppError,
    sideload::{SideloaderGuard, SideloaderMutex},
};

#[derive(Debug, Clone)]
struct BundleTarget {
    role: String,
    name: String,
    bundle_identifier: String,
    signing_bundle_identifier: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SigningBundleProfileInfo {
    pub role: String,
    pub name: String,
    pub bundle_identifier: String,
    pub signing_bundle_identifier: String,
    pub profile_uuid: String,
    pub profile_name: String,
    pub profile_expiration_date: String,
    pub is_free_provisioning_profile: Option<bool>,
    pub archive_path: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SigningBundleExportInfo {
    pub archive_path: String,
    pub p12_password: String,
    pub team_id: String,
    pub certificate_serial_number: String,
    pub profiles: Vec<SigningBundleProfileInfo>,
    pub checksums: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SigningBundleMetadata<'a> {
    format_version: u32,
    source_ipa: &'a str,
    team_id: &'a str,
    certificate_serial_number: &'a str,
    machine_id: &'a str,
    machine_name: &'a str,
    profiles: &'a [SigningBundleProfileInfo],
    checksum_algorithm: &'static str,
    password_embedded: bool,
}

fn sanitize_filename(value: &str) -> String {
    let sanitized: String = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
                ch
            } else {
                '_'
            }
        })
        .collect();
    let trimmed = sanitized.trim_matches('_');
    if trimmed.is_empty() {
        "bundle".into()
    } else {
        trimmed.to_string()
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn zip_error(context: &str, error: impl std::fmt::Display) -> AppError {
    AppError::Filesystem(context.into(), error.to_string())
}

fn add_zip_file(
    writer: &mut ZipWriter<File>,
    path: &str,
    bytes: &[u8],
    options: SimpleFileOptions,
) -> Result<(), AppError> {
    writer
        .start_file(path, options)
        .map_err(|error| zip_error("Failed to create signing-bundle ZIP entry", error))?;
    writer
        .write_all(bytes)
        .map_err(|error| zip_error("Failed to write signing-bundle ZIP entry", error))?;
    Ok(())
}

fn build_targets(application: &Application, team_id: &str) -> Result<Vec<BundleTarget>, AppError> {
    let main_bundle_id = application.main_bundle_id()?;
    let signing_main_bundle_id = format!("{}.{}", main_bundle_id, team_id);
    let mut targets = vec![BundleTarget {
        role: "main".into(),
        name: application.main_app_name()?,
        bundle_identifier: main_bundle_id.clone(),
        signing_bundle_identifier: signing_main_bundle_id.clone(),
    }];

    for extension in application.bundle.app_extensions() {
        let bundle_identifier = extension.bundle_identifier().unwrap_or("").to_string();
        if !bundle_identifier.starts_with(&main_bundle_id)
            || bundle_identifier.len() <= main_bundle_id.len()
        {
            return Err(AppError::Misc(format!(
                "Extension bundle identifier {} is not derived from main bundle identifier {}",
                bundle_identifier, main_bundle_id
            )));
        }

        let signing_bundle_identifier = format!(
            "{}{}",
            signing_main_bundle_id,
            &bundle_identifier[main_bundle_id.len()..]
        );
        targets.push(BundleTarget {
            role: "extension".into(),
            name: extension.bundle_name().unwrap_or("Extension").to_string(),
            bundle_identifier,
            signing_bundle_identifier,
        });
    }

    Ok(targets)
}

#[tauri::command]
pub async fn export_ipa_signing_bundle(
    handle: AppHandle,
    sideloader_state: State<'_, SideloaderMutex>,
    ipa_path: String,
    password: Option<String>,
) -> Result<Option<SigningBundleExportInfo>, AppError> {
    let directory = handle
        .dialog()
        .file()
        .set_title("Choose a folder for the complete signing bundle")
        .blocking_pick_folder();
    let Some(directory) = directory else {
        return Ok(None);
    };
    let output_dir = directory
        .into_path()
        .map_err(|error| AppError::Filesystem("Invalid export directory".into(), error.to_string()))?;

    let application = Application::new(PathBuf::from(&ipa_path))?;
    let mut sideloader = SideloaderGuard::take(&sideloader_state)?;
    let team = sideloader.get_mut().get_team().await?;
    let team_id = team.team_id.clone();
    let targets = build_targets(&application, &team_id)?;

    let app_ids = sideloader
        .get_mut()
        .get_dev_session()
        .list_app_ids(&team, None)
        .await?
        .app_ids;

    let identity = sideloader
        .get_mut()
        .export_signing_identity(password.as_deref())
        .await?;

    let options = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Deflated)
        .unix_permissions(0o600);

    let source_stem = Path::new(&ipa_path)
        .file_stem()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty())
        .unwrap_or("app");
    let archive_path = output_dir.join(format!(
        "{}-signing-bundle.zip",
        sanitize_filename(source_stem)
    ));
    let archive_file = File::create(&archive_path).map_err(|error| {
        AppError::Filesystem("Failed to create signing-bundle ZIP".into(), error.to_string())
    })?;
    let mut writer = ZipWriter::new(archive_file);

    let mut checksum_lines = Vec::new();
    add_zip_file(&mut writer, "development.p12", &identity.p12, options)?;
    checksum_lines.push(format!(
        "{}  development.p12",
        sha256_hex(&identity.p12)
    ));

    let mut profiles = Vec::with_capacity(targets.len());
    for (index, target) in targets.iter().enumerate() {
        let app_id = app_ids
            .iter()
            .find(|app_id| app_id.identifier == target.signing_bundle_identifier)
            .ok_or_else(|| {
                AppError::Misc(format!(
                    "No App ID exists for {}. Sign the IPA once or refresh/register the App ID before exporting the complete bundle.",
                    target.signing_bundle_identifier
                ))
            })?;

        let profile = sideloader
            .get_mut()
            .export_provisioning_profile(&app_id.app_id_id)
            .await?;
        let profile_path = if target.role == "main" {
            "profiles/main.mobileprovision".to_string()
        } else {
            format!(
                "profiles/extensions/{:02}-{}.mobileprovision",
                index,
                sanitize_filename(&target.name)
            )
        };

        add_zip_file(&mut writer, &profile_path, &profile.mobileprovision, options)?;
        checksum_lines.push(format!(
            "{}  {}",
            sha256_hex(&profile.mobileprovision),
            profile_path
        ));
        profiles.push(SigningBundleProfileInfo {
            role: target.role.clone(),
            name: target.name.clone(),
            bundle_identifier: target.bundle_identifier.clone(),
            signing_bundle_identifier: target.signing_bundle_identifier.clone(),
            profile_uuid: profile.uuid,
            profile_name: profile.name,
            profile_expiration_date: profile.expiration_date,
            is_free_provisioning_profile: profile.is_free_provisioning_profile,
            archive_path: profile_path,
        });
    }

    let metadata = SigningBundleMetadata {
        format_version: 1,
        source_ipa: &ipa_path,
        team_id: &identity.team_id,
        certificate_serial_number: &identity.certificate_serial_number,
        machine_id: &identity.machine_id,
        machine_name: &identity.machine_name,
        profiles: &profiles,
        checksum_algorithm: "SHA-256",
        password_embedded: false,
    };
    let metadata_bytes = serde_json::to_vec_pretty(&metadata)
        .map_err(|error| AppError::Misc(format!("Failed to serialize signing-bundle metadata: {error}")))?;
    add_zip_file(&mut writer, "metadata.json", &metadata_bytes, options)?;
    checksum_lines.push(format!(
        "{}  metadata.json",
        sha256_hex(&metadata_bytes)
    ));

    let checksums_bytes = format!("{}\n", checksum_lines.join("\n")).into_bytes();
    add_zip_file(&mut writer, "checksums.sha256", &checksums_bytes, options)?;
    writer
        .finish()
        .map_err(|error| zip_error("Failed to finalize signing-bundle ZIP", error))?;

    Ok(Some(SigningBundleExportInfo {
        archive_path: archive_path.display().to_string(),
        p12_password: identity.p12_password,
        team_id: identity.team_id,
        certificate_serial_number: identity.certificate_serial_number,
        profiles,
        checksums: checksum_lines,
    }))
}
