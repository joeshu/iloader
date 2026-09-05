use std::{collections::BTreeSet, fs, path::PathBuf};

use apple_codesign::ProvisioningProfile;
use isideload::{
    dev::app_ids::AppIdsApi,
    sideload::{application::Application, bundle::Bundle},
};
use plist::Dictionary;
use serde::Serialize;
use tauri::State;

use crate::{
    error::AppError,
    sideload::{SideloaderGuard, SideloaderMutex},
};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum EntitlementCompatibilityStatus {
    Preserved,
    Rewritten,
    Added,
    Unsupported,
    PendingRegistration,
    SourceUnavailable,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum EntitlementCompatibilitySeverity {
    Info,
    Warning,
    Error,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EntitlementCompatibilityItem {
    pub key: String,
    pub status: EntitlementCompatibilityStatus,
    pub severity: EntitlementCompatibilitySeverity,
    pub source_value: Option<String>,
    pub target_value: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BundleEntitlementCompatibility {
    pub role: String,
    pub name: String,
    pub bundle_identifier: String,
    pub signing_bundle_identifier: String,
    pub source_profile_available: bool,
    pub target_profile_available: bool,
    pub blocking: bool,
    pub items: Vec<EntitlementCompatibilityItem>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EntitlementCompatibilityReport {
    pub ready: bool,
    pub team_id: String,
    pub bundles: Vec<BundleEntitlementCompatibility>,
    pub blocking_count: usize,
    pub warning_count: usize,
}

struct BundleTarget<'a> {
    role: &'static str,
    bundle: &'a Bundle,
    name: String,
    bundle_identifier: String,
    signing_bundle_identifier: String,
}

fn entitlement_value(value: &plist::Value) -> String {
    format!("{value:?}")
}

fn expected_rewrite_key(key: &str) -> bool {
    matches!(
        key,
        "application-identifier"
            | "com.apple.developer.team-identifier"
            | "keychain-access-groups"
            | "get-task-allow"
            | "beta-reports-active"
    )
}

fn capability_sensitive_key(key: &str) -> bool {
    matches!(
        key,
        "aps-environment"
            | "com.apple.developer.associated-domains"
            | "com.apple.security.application-groups"
            | "com.apple.developer.icloud-container-identifiers"
            | "com.apple.developer.icloud-services"
            | "com.apple.developer.ubiquity-container-identifiers"
            | "com.apple.developer.ubiquity-kvstore-identifier"
            | "com.apple.developer.healthkit"
            | "com.apple.developer.applesignin"
            | "com.apple.developer.networking.networkextension"
            | "com.apple.developer.networking.vpn.api"
            | "com.apple.developer.homekit"
    )
}

fn profile_entitlements(bytes: &[u8]) -> Result<Dictionary, AppError> {
    let profile = ProvisioningProfile::parse(bytes)
        .map_err(|error| AppError::Misc(format!("Failed to parse provisioning profile: {error}")))?;
    Ok(profile.entitlements().clone())
}

fn embedded_profile_entitlements(bundle: &Bundle) -> Result<Option<Dictionary>, AppError> {
    let path = bundle.bundle_dir.join("embedded.mobileprovision");
    if !path.exists() {
        return Ok(None);
    }
    let bytes = fs::read(&path).map_err(|error| {
        AppError::Filesystem(
            format!("Failed to read source provisioning profile at {}", path.display()),
            error.to_string(),
        )
    })?;
    profile_entitlements(&bytes).map(Some)
}

fn compare_entitlements(
    source: Option<&Dictionary>,
    target: Option<&Dictionary>,
    target_pending_registration: bool,
) -> Vec<EntitlementCompatibilityItem> {
    let mut keys = BTreeSet::new();
    if let Some(source) = source {
        keys.extend(source.keys().cloned());
    }
    if let Some(target) = target {
        keys.extend(target.keys().cloned());
    }

    if source.is_none() {
        return vec![EntitlementCompatibilityItem {
            key: "source.profile".into(),
            status: EntitlementCompatibilityStatus::SourceUnavailable,
            severity: EntitlementCompatibilitySeverity::Warning,
            source_value: None,
            target_value: None,
            message: "The source IPA has no embedded provisioning profile, so original entitlement compatibility cannot be proven before signing.".into(),
        }];
    }

    let source = source.expect("checked above");
    let mut items = Vec::new();
    for key in keys {
        let source_value = source.get(&key);
        let target_value = target.and_then(|target| target.get(&key));

        let (status, severity, message) = match (source_value, target_value) {
            (Some(source_value), Some(target_value)) if source_value == target_value => (
                EntitlementCompatibilityStatus::Preserved,
                EntitlementCompatibilitySeverity::Info,
                format!("Entitlement {key} is preserved by the target provisioning profile."),
            ),
            (Some(_), Some(_)) if expected_rewrite_key(&key) => (
                EntitlementCompatibilityStatus::Rewritten,
                EntitlementCompatibilitySeverity::Info,
                format!("Entitlement {key} will be rewritten for the selected developer team/signing identity."),
            ),
            (Some(_), Some(_)) => {
                let severity = if capability_sensitive_key(&key) {
                    EntitlementCompatibilitySeverity::Error
                } else {
                    EntitlementCompatibilitySeverity::Warning
                };
                (
                    EntitlementCompatibilityStatus::Rewritten,
                    severity,
                    format!("Entitlement {key} differs from the source IPA and will change after signing."),
                )
            }
            (Some(_), None) if target_pending_registration => {
                let severity = if capability_sensitive_key(&key) {
                    EntitlementCompatibilitySeverity::Error
                } else {
                    EntitlementCompatibilitySeverity::Warning
                };
                (
                    EntitlementCompatibilityStatus::PendingRegistration,
                    severity,
                    format!("Entitlement {key} exists in the source IPA, but the target App ID does not exist yet. The current signing engine cannot guarantee this entitlement will be recreated automatically."),
                )
            }
            (Some(_), None) => {
                let severity = if capability_sensitive_key(&key) {
                    EntitlementCompatibilitySeverity::Error
                } else {
                    EntitlementCompatibilitySeverity::Warning
                };
                (
                    EntitlementCompatibilityStatus::Unsupported,
                    severity,
                    format!("Entitlement {key} exists in the source IPA but is absent from the target provisioning profile."),
                )
            }
            (None, Some(_)) => (
                EntitlementCompatibilityStatus::Added,
                EntitlementCompatibilitySeverity::Info,
                format!("Entitlement {key} will be added by the target provisioning profile."),
            ),
            (None, None) => continue,
        };

        items.push(EntitlementCompatibilityItem {
            key,
            status,
            severity,
            source_value: source_value.map(entitlement_value),
            target_value: target_value.map(entitlement_value),
            message,
        });
    }
    items
}

fn build_targets<'a>(application: &'a Application, team_id: &str) -> Result<Vec<BundleTarget<'a>>, AppError> {
    let main_bundle_id = application.main_bundle_id()?;
    let signing_main_bundle_id = format!("{}.{}", main_bundle_id, team_id);
    let mut targets = vec![BundleTarget {
        role: "main",
        bundle: &application.bundle,
        name: application.main_app_name()?,
        bundle_identifier: main_bundle_id.clone(),
        signing_bundle_identifier: signing_main_bundle_id.clone(),
    }];

    for extension in application.bundle.app_extensions() {
        let bundle_identifier = extension.bundle_identifier().unwrap_or("").to_string();
        if !bundle_identifier.starts_with(&main_bundle_id) || bundle_identifier.len() <= main_bundle_id.len() {
            return Err(AppError::Misc(format!(
                "Extension bundle identifier {bundle_identifier} is not derived from main bundle identifier {main_bundle_id}"
            )));
        }
        targets.push(BundleTarget {
            role: "extension",
            bundle: extension,
            name: extension.bundle_name().unwrap_or("Extension").to_string(),
            signing_bundle_identifier: format!(
                "{}{}",
                signing_main_bundle_id,
                &bundle_identifier[main_bundle_id.len()..]
            ),
            bundle_identifier,
        });
    }
    Ok(targets)
}

#[tauri::command]
pub async fn preflight_ipa_entitlements(
    sideloader_state: State<'_, SideloaderMutex>,
    ipa_path: String,
) -> Result<EntitlementCompatibilityReport, AppError> {
    let application = Application::new(PathBuf::from(&ipa_path))?;
    let mut sideloader = SideloaderGuard::take(&sideloader_state)?;
    let team = sideloader.get_mut().get_team().await?;
    let team_id = team.team_id.clone();
    let app_ids = sideloader
        .get_mut()
        .get_dev_session()
        .list_app_ids(&team, None)
        .await?
        .app_ids;
    let targets = build_targets(&application, &team_id)?;

    let mut bundles = Vec::with_capacity(targets.len());
    let mut blocking_count = 0usize;
    let mut warning_count = 0usize;

    for target in targets {
        let source = embedded_profile_entitlements(target.bundle)?;
        let matching_app_id = app_ids
            .iter()
            .find(|app_id| app_id.identifier == target.signing_bundle_identifier);
        let target_entitlements = if let Some(app_id) = matching_app_id {
            let profile = sideloader
                .get_mut()
                .get_dev_session()
                .download_team_provisioning_profile(&team, app_id, None)
                .await?;
            Some(profile_entitlements(profile.encoded_profile.as_ref())?)
        } else {
            None
        };
        let items = compare_entitlements(source.as_ref(), target_entitlements.as_ref(), matching_app_id.is_none());
        let blocking = items.iter().any(|item| matches!(item.severity, EntitlementCompatibilitySeverity::Error));
        blocking_count += items.iter().filter(|item| matches!(item.severity, EntitlementCompatibilitySeverity::Error)).count();
        warning_count += items.iter().filter(|item| matches!(item.severity, EntitlementCompatibilitySeverity::Warning)).count();

        bundles.push(BundleEntitlementCompatibility {
            role: target.role.into(),
            name: target.name,
            bundle_identifier: target.bundle_identifier,
            signing_bundle_identifier: target.signing_bundle_identifier,
            source_profile_available: source.is_some(),
            target_profile_available: target_entitlements.is_some(),
            blocking,
            items,
        });
    }

    Ok(EntitlementCompatibilityReport {
        ready: blocking_count == 0,
        team_id,
        bundles,
        blocking_count,
        warning_count,
    })
}
