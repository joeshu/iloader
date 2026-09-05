use std::{fs::File, io::Read, path::Path};

use serde::Serialize;
use zip::ZipArchive;

use crate::error::AppError;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedIpaValidation {
    pub valid: bool,
    pub payload_app: Option<String>,
    pub has_info_plist: bool,
    pub has_code_signature: bool,
    pub has_provisioning_profile: bool,
    pub extension_count: usize,
    pub extension_profiles: usize,
    pub checks: Vec<SignedIpaValidationCheck>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedIpaValidationCheck {
    pub code: String,
    pub passed: bool,
    pub message: String,
}

fn check(code: &str, passed: bool, message: impl Into<String>) -> SignedIpaValidationCheck {
    SignedIpaValidationCheck { code: code.into(), passed, message: message.into() }
}

pub fn validate_signed_ipa_path(path: &Path) -> Result<SignedIpaValidation, AppError> {
    let file = File::open(path).map_err(|e| AppError::Filesystem("Failed to open signed IPA for validation".into(), e.to_string()))?;
    let mut archive = ZipArchive::new(file).map_err(|e| AppError::Filesystem("Signed IPA is not a readable ZIP archive".into(), e.to_string()))?;
    let mut names = Vec::with_capacity(archive.len());
    for index in 0..archive.len() {
        let entry = archive.by_index(index).map_err(|e| AppError::Filesystem("Failed to inspect signed IPA archive".into(), e.to_string()))?;
        names.push(entry.name().replace('\\', "/"));
    }

    let payload_app = names.iter().find_map(|name| {
        let rest = name.strip_prefix("Payload/")?;
        let first = rest.split('/').next()?;
        first.ends_with(".app").then(|| first.to_string())
    });

    let root = payload_app.as_ref().map(|app| format!("Payload/{app}/"));
    let has_info_plist = root.as_ref().is_some_and(|root| names.iter().any(|n| n == &format!("{root}Info.plist")));
    let has_code_signature = root.as_ref().is_some_and(|root| names.iter().any(|n| n.starts_with(&format!("{root}_CodeSignature/"))));
    let has_provisioning_profile = root.as_ref().is_some_and(|root| names.iter().any(|n| n == &format!("{root}embedded.mobileprovision")));

    let mut extension_roots = std::collections::HashSet::new();
    if let Some(root) = root.as_ref() {
        let plugins = format!("{root}PlugIns/");
        for name in &names {
            if let Some(rest) = name.strip_prefix(&plugins) {
                if let Some(first) = rest.split('/').next() {
                    if first.ends_with(".appex") { extension_roots.insert(format!("{plugins}{first}/")); }
                }
            }
        }
    }
    let extension_count = extension_roots.len();
    let extension_profiles = extension_roots.iter().filter(|extension_root| names.iter().any(|n| n == &format!("{extension_root}embedded.mobileprovision"))).count();
    let extensions_have_profiles = extension_count == extension_profiles;

    let checks = vec![
        check("archive.payload_app", payload_app.is_some(), "IPA contains a Payload/*.app root."),
        check("archive.info_plist", has_info_plist, "Main app contains Info.plist."),
        check("signature.code_signature", has_code_signature, "Main app contains _CodeSignature."),
        check("profile.main", has_provisioning_profile, "Main app contains embedded.mobileprovision."),
        check("profile.extensions", extensions_have_profiles, format!("{extension_profiles}/{extension_count} app extension(s) contain embedded.mobileprovision.")),
    ];
    let valid = checks.iter().all(|item| item.passed);

    Ok(SignedIpaValidation { valid, payload_app, has_info_plist, has_code_signature, has_provisioning_profile, extension_count, extension_profiles, checks })
}

#[tauri::command]
pub async fn validate_signed_ipa(ipa_path: String) -> Result<SignedIpaValidation, AppError> {
    validate_signed_ipa_path(Path::new(&ipa_path))
}
