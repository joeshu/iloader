use std::{collections::{HashMap, HashSet}, fs::File, io::Read, path::{Component, Path, PathBuf}};

use apple_codesign::ProvisioningProfile;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tauri::State;
use zip::ZipArchive;

use crate::{
    error::AppError,
    sideload::{SideloaderGuard, SideloaderMutex},
};

const MAX_ENTRY_BYTES: u64 = 32 * 1024 * 1024;
const MAX_ARCHIVE_ENTRIES: usize = 256;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ImportProfileMetadata {
    role: String,
    name: String,
    bundle_identifier: String,
    signing_bundle_identifier: String,
    profile_uuid: String,
    profile_name: String,
    profile_expiration_date: String,
    is_free_provisioning_profile: Option<bool>,
    archive_path: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ImportBundleMetadata {
    format_version: u32,
    source_ipa: String,
    team_id: String,
    certificate_serial_number: String,
    machine_id: String,
    machine_name: String,
    profiles: Vec<ImportProfileMetadata>,
    checksum_algorithm: String,
    password_embedded: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SigningBundleImportSeverity {
    Info,
    Warning,
    Error,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SigningBundleImportCheck {
    pub code: String,
    pub severity: SigningBundleImportSeverity,
    pub passed: bool,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SigningBundleImportedProfile {
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
pub struct SigningBundleImportReport {
    pub valid: bool,
    pub can_activate: bool,
    pub archive_path: String,
    pub source_ipa: String,
    pub team_id: String,
    pub current_team_id: String,
    pub certificate_serial_number: String,
    pub profile_count: usize,
    pub profiles: Vec<SigningBundleImportedProfile>,
    pub checks: Vec<SigningBundleImportCheck>,
}

fn check(
    code: &str,
    severity: SigningBundleImportSeverity,
    passed: bool,
    message: impl Into<String>,
) -> SigningBundleImportCheck {
    SigningBundleImportCheck {
        code: code.into(),
        severity,
        passed,
        message: message.into(),
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn safe_archive_path(path: &str) -> bool {
    if path.is_empty() || path.contains('\\') {
        return false;
    }
    let parsed = Path::new(path);
    !parsed.is_absolute()
        && parsed.components().all(|component| {
            matches!(component, Component::Normal(_))
        })
}

fn read_entry(
    archive: &mut ZipArchive<File>,
    name: &str,
) -> Result<Vec<u8>, AppError> {
    let mut entry = archive
        .by_name(name)
        .map_err(|error| AppError::Misc(format!("Signing bundle is missing {name}: {error}")))?;
    if entry.size() > MAX_ENTRY_BYTES {
        return Err(AppError::Misc(format!(
            "Signing bundle entry {name} is too large ({} bytes)",
            entry.size()
        )));
    }
    let mut bytes = Vec::with_capacity(entry.size() as usize);
    entry
        .read_to_end(&mut bytes)
        .map_err(|error| AppError::Filesystem(format!("Failed to read {name}"), error.to_string()))?;
    Ok(bytes)
}

fn parse_checksums(bytes: &[u8]) -> Result<HashMap<String, String>, AppError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|error| AppError::Misc(format!("checksums.sha256 is not UTF-8: {error}")))?;
    let mut checksums = HashMap::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Some((digest, path)) = line.split_once("  ") else {
            return Err(AppError::Misc(format!(
                "Invalid checksums.sha256 line {}",
                index + 1
            )));
        };
        if digest.len() != 64 || !digest.chars().all(|ch| ch.is_ascii_hexdigit()) {
            return Err(AppError::Misc(format!(
                "Invalid SHA-256 digest on line {}",
                index + 1
            )));
        }
        if !safe_archive_path(path) {
            return Err(AppError::Misc(format!("Unsafe checksum path: {path}")));
        }
        if checksums.insert(path.to_string(), digest.to_ascii_lowercase()).is_some() {
            return Err(AppError::Misc(format!("Duplicate checksum entry: {path}")));
        }
    }
    Ok(checksums)
}

fn profile_application_identifier(profile: &ProvisioningProfile) -> Option<&str> {
    profile
        .entitlements()
        .get("application-identifier")
        .and_then(|value| value.as_string())
}

fn profile_team_identifier(profile: &ProvisioningProfile) -> Option<&str> {
    profile
        .entitlements()
        .get("com.apple.developer.team-identifier")
        .and_then(|value| value.as_string())
}

#[tauri::command]
pub async fn inspect_signing_bundle_import(
    sideloader_state: State<'_, SideloaderMutex>,
    archive_path: String,
) -> Result<SigningBundleImportReport, AppError> {
    let path = PathBuf::from(&archive_path);
    let file = File::open(&path).map_err(|error| {
        AppError::Filesystem("Failed to open signing bundle".into(), error.to_string())
    })?;
    let mut archive = ZipArchive::new(file)
        .map_err(|error| AppError::Misc(format!("Invalid signing-bundle ZIP: {error}")))?;
    if archive.len() > MAX_ARCHIVE_ENTRIES {
        return Err(AppError::Misc(format!(
            "Signing bundle contains too many entries: {}",
            archive.len()
        )));
    }

    let mut seen_names = HashSet::new();
    for index in 0..archive.len() {
        let entry = archive
            .by_index(index)
            .map_err(|error| AppError::Misc(format!("Failed to inspect ZIP entry: {error}")))?;
        let name = entry.name().to_string();
        if !safe_archive_path(name.trim_end_matches('/')) && !name.ends_with('/') {
            return Err(AppError::Misc(format!("Unsafe ZIP entry path: {name}")));
        }
        if !seen_names.insert(name.clone()) {
            return Err(AppError::Misc(format!("Duplicate ZIP entry: {name}")));
        }
        if !entry.is_dir() && entry.size() > MAX_ENTRY_BYTES {
            return Err(AppError::Misc(format!(
                "Signing bundle entry {name} is too large ({} bytes)",
                entry.size()
            )));
        }
    }

    let metadata_bytes = read_entry(&mut archive, "metadata.json")?;
    let checksum_bytes = read_entry(&mut archive, "checksums.sha256")?;
    let p12_bytes = read_entry(&mut archive, "development.p12")?;
    let metadata: ImportBundleMetadata = serde_json::from_slice(&metadata_bytes)
        .map_err(|error| AppError::Misc(format!("Invalid signing-bundle metadata.json: {error}")))?;
    let checksums = parse_checksums(&checksum_bytes)?;

    let mut sideloader = SideloaderGuard::take(&sideloader_state)?;
    let current_team = sideloader.get_mut().get_team().await?;
    let current_team_id = current_team.team_id.clone();
    drop(sideloader);

    let mut checks = Vec::new();
    checks.push(check(
        "format.version",
        SigningBundleImportSeverity::Error,
        metadata.format_version == 1,
        format!("Signing bundle format version is {} (supported: 1).", metadata.format_version),
    ));
    checks.push(check(
        "checksum.algorithm",
        SigningBundleImportSeverity::Error,
        metadata.checksum_algorithm.eq_ignore_ascii_case("SHA-256"),
        format!("Checksum algorithm is {}.", metadata.checksum_algorithm),
    ));
    checks.push(check(
        "password.not_embedded",
        SigningBundleImportSeverity::Error,
        !metadata.password_embedded,
        if metadata.password_embedded {
            "Bundle metadata claims that the PKCS#12 password is embedded, which is not accepted.".into()
        } else {
            "PKCS#12 password is not embedded in metadata.".into()
        },
    ));
    checks.push(check(
        "team.matches",
        SigningBundleImportSeverity::Error,
        metadata.team_id == current_team_id,
        if metadata.team_id == current_team_id {
            format!("Bundle team {} matches the active developer team.", metadata.team_id)
        } else {
            format!(
                "Bundle team {} does not match active team {}.",
                metadata.team_id, current_team_id
            )
        },
    ));
    checks.push(check(
        "p12.present",
        SigningBundleImportSeverity::Error,
        !p12_bytes.is_empty(),
        if p12_bytes.is_empty() {
            "development.p12 is empty.".into()
        } else {
            format!("development.p12 is present ({} bytes).", p12_bytes.len())
        },
    ));

    let required_checksum_paths = std::iter::once("development.p12".to_string())
        .chain(std::iter::once("metadata.json".to_string()))
        .chain(metadata.profiles.iter().map(|profile| profile.archive_path.clone()))
        .collect::<Vec<_>>();
    let mut all_checksums_valid = true;
    for entry_path in &required_checksum_paths {
        if !safe_archive_path(entry_path) {
            all_checksums_valid = false;
            checks.push(check(
                "checksum.path",
                SigningBundleImportSeverity::Error,
                false,
                format!("Unsafe declared archive path: {entry_path}"),
            ));
            continue;
        }
        let bytes = if entry_path == "development.p12" {
            p12_bytes.clone()
        } else if entry_path == "metadata.json" {
            metadata_bytes.clone()
        } else {
            read_entry(&mut archive, entry_path)?
        };
        let actual = sha256_hex(&bytes);
        let expected = checksums.get(entry_path);
        let valid = expected.is_some_and(|digest| digest == &actual);
        all_checksums_valid &= valid;
        checks.push(check(
            format!("checksum.{entry_path}").as_str(),
            SigningBundleImportSeverity::Error,
            valid,
            if valid {
                format!("SHA-256 verified for {entry_path}.")
            } else {
                format!("SHA-256 mismatch or missing checksum for {entry_path}.")
            },
        ));
    }

    let mut unique_profile_paths = HashSet::new();
    let mut unique_profile_uuids = HashSet::new();
    let mut main_profiles = 0usize;
    let mut profile_validation_ok = true;
    for profile_meta in &metadata.profiles {
        if profile_meta.role == "main" {
            main_profiles += 1;
        }
        let unique_path = unique_profile_paths.insert(profile_meta.archive_path.clone());
        let unique_uuid = unique_profile_uuids.insert(profile_meta.profile_uuid.clone());
        if !unique_path || !unique_uuid {
            profile_validation_ok = false;
        }

        let bytes = read_entry(&mut archive, &profile_meta.archive_path)?;
        let parsed = ProvisioningProfile::parse(&bytes).map_err(|error| {
            AppError::Misc(format!(
                "Failed to parse {} as a provisioning profile: {error}",
                profile_meta.archive_path
            ))
        })?;
        let expected_application_identifier = format!(
            "{}.{}",
            metadata.team_id, profile_meta.signing_bundle_identifier
        );
        let application_identifier_matches = profile_application_identifier(&parsed)
            .is_some_and(|value| value == expected_application_identifier);
        let team_matches = profile_team_identifier(&parsed)
            .map(|value| value == metadata.team_id)
            .unwrap_or(true);
        profile_validation_ok &= application_identifier_matches && team_matches;
        checks.push(check(
            format!("profile.{}", profile_meta.archive_path).as_str(),
            SigningBundleImportSeverity::Error,
            application_identifier_matches && team_matches,
            if application_identifier_matches && team_matches {
                format!(
                    "Provisioning profile {} matches signing identifier {} and team {}.",
                    profile_meta.profile_name, profile_meta.signing_bundle_identifier, metadata.team_id
                )
            } else {
                format!(
                    "Provisioning profile {} does not match declared signing identifier/team.",
                    profile_meta.profile_name
                )
            },
        ));
    }

    let profile_shape_valid = main_profiles == 1
        && !metadata.profiles.is_empty()
        && unique_profile_paths.len() == metadata.profiles.len()
        && unique_profile_uuids.len() == metadata.profiles.len();
    checks.push(check(
        "profiles.structure",
        SigningBundleImportSeverity::Error,
        profile_shape_valid,
        format!(
            "Bundle declares {} profile(s), including {} main profile(s).",
            metadata.profiles.len(), main_profiles
        ),
    ));

    checks.push(check(
        "activation.password_required",
        SigningBundleImportSeverity::Info,
        true,
        "Integrity inspection does not decrypt or activate development.p12. Activation must require the separately supplied PKCS#12 password.",
    ));

    let valid = checks.iter().all(|item| {
        !matches!(item.severity, SigningBundleImportSeverity::Error) || item.passed
    }) && all_checksums_valid && profile_validation_ok && profile_shape_valid;

    Ok(SigningBundleImportReport {
        valid,
        can_activate: valid,
        archive_path,
        source_ipa: metadata.source_ipa,
        team_id: metadata.team_id,
        current_team_id,
        certificate_serial_number: metadata.certificate_serial_number,
        profile_count: metadata.profiles.len(),
        profiles: metadata
            .profiles
            .into_iter()
            .map(|profile| SigningBundleImportedProfile {
                role: profile.role,
                name: profile.name,
                bundle_identifier: profile.bundle_identifier,
                signing_bundle_identifier: profile.signing_bundle_identifier,
                profile_uuid: profile.profile_uuid,
                profile_name: profile.profile_name,
                profile_expiration_date: profile.profile_expiration_date,
                is_free_provisioning_profile: profile.is_free_provisioning_profile,
                archive_path: profile.archive_path,
            })
            .collect(),
        checks,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_path_traversal_and_backslashes() {
        assert!(safe_archive_path("profiles/main.mobileprovision"));
        assert!(!safe_archive_path("../development.p12"));
        assert!(!safe_archive_path("profiles\\main.mobileprovision"));
        assert!(!safe_archive_path("/absolute/path"));
    }

    #[test]
    fn checksum_parser_rejects_duplicates() {
        let data = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  metadata.json\naaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  metadata.json\n";
        assert!(parse_checksums(data).is_err());
    }
}
