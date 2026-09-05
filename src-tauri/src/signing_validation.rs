use std::{fs::File, path::Path};

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
    SignedIpaValidationCheck {
        code: code.into(),
        passed,
        message: message.into(),
    }
}

pub fn validate_signed_ipa_path(path: &Path) -> Result<SignedIpaValidation, AppError> {
    let file = File::open(path).map_err(|error| {
        AppError::Filesystem(
            "Failed to open signed IPA for validation".into(),
            error.to_string(),
        )
    })?;
    let mut archive = ZipArchive::new(file).map_err(|error| {
        AppError::Filesystem(
            "Signed IPA is not a readable ZIP archive".into(),
            error.to_string(),
        )
    })?;

    let mut names = Vec::with_capacity(archive.len());
    for index in 0..archive.len() {
        let entry = archive.by_index(index).map_err(|error| {
            AppError::Filesystem(
                "Failed to inspect signed IPA archive".into(),
                error.to_string(),
            )
        })?;
        names.push(entry.name().replace('\\', "/"));
    }

    let payload_app = names.iter().find_map(|name| {
        let rest = name.strip_prefix("Payload/")?;
        let first = rest.split('/').next()?;
        first.ends_with(".app").then(|| first.to_string())
    });

    let root = payload_app.as_ref().map(|app| format!("Payload/{app}/"));
    let has_info_plist = root
        .as_ref()
        .is_some_and(|root| names.iter().any(|name| name == &format!("{root}Info.plist")));
    let has_code_signature = root.as_ref().is_some_and(|root| {
        names
            .iter()
            .any(|name| name.starts_with(&format!("{root}_CodeSignature/")))
    });
    let has_provisioning_profile = root.as_ref().is_some_and(|root| {
        names
            .iter()
            .any(|name| name == &format!("{root}embedded.mobileprovision"))
    });

    let mut extension_roots = std::collections::HashSet::new();
    if let Some(root) = root.as_ref() {
        let plugins = format!("{root}PlugIns/");
        for name in &names {
            if let Some(rest) = name.strip_prefix(&plugins)
                && let Some(first) = rest.split('/').next()
                && first.ends_with(".appex")
            {
                extension_roots.insert(format!("{plugins}{first}/"));
            }
        }
    }

    let extension_count = extension_roots.len();
    let extension_profiles = extension_roots
        .iter()
        .filter(|extension_root| {
            names
                .iter()
                .any(|name| name == &format!("{extension_root}embedded.mobileprovision"))
        })
        .count();
    let extensions_have_profiles = extension_count == extension_profiles;

    let checks = vec![
        check(
            "archive.payload_app",
            payload_app.is_some(),
            "IPA contains a Payload/*.app root.",
        ),
        check(
            "archive.info_plist",
            has_info_plist,
            "Main app contains Info.plist.",
        ),
        check(
            "signature.code_signature",
            has_code_signature,
            "Main app contains _CodeSignature.",
        ),
        check(
            "profile.main",
            has_provisioning_profile,
            "Main app contains embedded.mobileprovision.",
        ),
        check(
            "profile.extensions",
            extensions_have_profiles,
            format!(
                "{extension_profiles}/{extension_count} app extension(s) contain embedded.mobileprovision."
            ),
        ),
    ];
    let valid = checks.iter().all(|item| item.passed);

    Ok(SignedIpaValidation {
        valid,
        payload_app,
        has_info_plist,
        has_code_signature,
        has_provisioning_profile,
        extension_count,
        extension_profiles,
        checks,
    })
}

#[tauri::command]
pub async fn validate_signed_ipa(ipa_path: String) -> Result<SignedIpaValidation, AppError> {
    validate_signed_ipa_path(Path::new(&ipa_path))
}

#[cfg(test)]
mod tests {
    use std::{
        fs::{self, File},
        io::Write,
        time::{SystemTime, UNIX_EPOCH},
    };

    use zip::{ZipWriter, write::SimpleFileOptions};

    use super::validate_signed_ipa_path;

    fn fixture_path(name: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be after epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("iloader-{name}-{nonce}.ipa"))
    }

    fn write_zip(path: &std::path::Path, entries: &[&str]) {
        let file = File::create(path).expect("fixture IPA should be created");
        let mut writer = ZipWriter::new(file);
        let options = SimpleFileOptions::default();
        for entry in entries {
            writer
                .start_file(*entry, options)
                .expect("fixture entry should be created");
            writer
                .write_all(b"fixture")
                .expect("fixture entry should be written");
        }
        writer.finish().expect("fixture ZIP should finalize");
    }

    #[test]
    fn accepts_structurally_complete_signed_ipa() {
        let path = fixture_path("valid");
        write_zip(
            &path,
            &[
                "Payload/Test.app/Info.plist",
                "Payload/Test.app/_CodeSignature/CodeResources",
                "Payload/Test.app/embedded.mobileprovision",
                "Payload/Test.app/PlugIns/Share.appex/Info.plist",
                "Payload/Test.app/PlugIns/Share.appex/embedded.mobileprovision",
            ],
        );

        let validation = validate_signed_ipa_path(&path).expect("validator should inspect fixture");
        assert!(validation.valid);
        assert_eq!(validation.extension_count, 1);
        assert_eq!(validation.extension_profiles, 1);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn rejects_missing_extension_profile() {
        let path = fixture_path("missing-extension-profile");
        write_zip(
            &path,
            &[
                "Payload/Test.app/Info.plist",
                "Payload/Test.app/_CodeSignature/CodeResources",
                "Payload/Test.app/embedded.mobileprovision",
                "Payload/Test.app/PlugIns/Share.appex/Info.plist",
            ],
        );

        let validation = validate_signed_ipa_path(&path).expect("validator should inspect fixture");
        assert!(!validation.valid);
        assert_eq!(validation.extension_count, 1);
        assert_eq!(validation.extension_profiles, 0);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn rejects_unsigned_payload() {
        let path = fixture_path("unsigned");
        write_zip(&path, &["Payload/Test.app/Info.plist"]);

        let validation = validate_signed_ipa_path(&path).expect("validator should inspect fixture");
        assert!(!validation.valid);
        assert!(!validation.has_code_signature);
        assert!(!validation.has_provisioning_profile);
        let _ = fs::remove_file(path);
    }
}
