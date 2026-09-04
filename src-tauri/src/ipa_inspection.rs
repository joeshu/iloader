use std::path::PathBuf;

use isideload::{
    dev::{
        app_ids::{AppId, AppIdsApi},
        certificates::CertificatesApi,
        devices::DevicesApi,
    },
    sideload::application::Application,
};
use serde::Serialize;
use tauri::State;

use crate::{
    error::AppError,
    sideload::{SideloaderGuard, SideloaderMutex},
};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IpaProfileMatch {
    pub app_id_id: String,
    pub identifier: String,
    pub name: String,
    pub profile_uuid: Option<String>,
    pub profile_name: Option<String>,
    pub profile_status: Option<String>,
    pub profile_expiration_date: Option<String>,
    pub is_free_provisioning_profile: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IpaBundleInspection {
    pub name: String,
    pub bundle_identifier: String,
    pub version: Option<String>,
    pub build: Option<String>,
    pub minimum_os_version: Option<String>,
    pub app_id_match: Option<IpaProfileMatch>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IpaInspectionResult {
    pub path: String,
    pub main: IpaBundleInspection,
    pub extensions: Vec<IpaBundleInspection>,
    pub all_bundle_ids_matched: bool,
    pub unmatched_bundle_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum AutoPreflightSeverity {
    Info,
    Warning,
    Error,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AutoPreflightCheck {
    pub code: String,
    pub severity: AutoPreflightSeverity,
    pub passed: bool,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AutoIpaPreflightReport {
    pub ready: bool,
    pub team_id: String,
    pub inspection: IpaInspectionResult,
    pub checks: Vec<AutoPreflightCheck>,
}

fn plist_string(bundle: &isideload::sideload::bundle::Bundle, key: &str) -> Option<String> {
    bundle
        .app_info
        .get(key)
        .and_then(|value| value.as_string())
        .map(ToString::to_string)
}

async fn profile_match(
    dev_session: &mut isideload::dev::developer_session::DeveloperSession,
    team: &isideload::dev::teams::DeveloperTeam,
    app_id: &AppId,
) -> Result<IpaProfileMatch, AppError> {
    let profile = dev_session
        .download_team_provisioning_profile(team, app_id, None)
        .await?;

    Ok(IpaProfileMatch {
        app_id_id: app_id.app_id_id.clone(),
        identifier: app_id.identifier.clone(),
        name: app_id.name.clone(),
        profile_uuid: Some(profile.uuid),
        profile_name: Some(profile.name),
        profile_status: Some(profile.status),
        profile_expiration_date: Some(format!("{:?}", profile.date_expire)),
        is_free_provisioning_profile: profile.is_free_provisioning_profile,
    })
}

async fn build_inspection(
    application: &Application,
    ipa_path: String,
    dev_session: &mut isideload::dev::developer_session::DeveloperSession,
    team: &isideload::dev::teams::DeveloperTeam,
    app_ids: &[AppId],
) -> Result<IpaInspectionResult, AppError> {
    let main_bundle_id = application.main_bundle_id()?;
    let main_app_id = app_ids
        .iter()
        .find(|app_id| app_id.identifier == main_bundle_id)
        .cloned();
    let main_match = if let Some(app_id) = main_app_id.as_ref() {
        Some(profile_match(dev_session, team, app_id).await?)
    } else {
        None
    };

    let main = IpaBundleInspection {
        name: application.main_app_name()?,
        bundle_identifier: main_bundle_id.clone(),
        version: plist_string(&application.bundle, "CFBundleShortVersionString"),
        build: plist_string(&application.bundle, "CFBundleVersion"),
        minimum_os_version: plist_string(&application.bundle, "MinimumOSVersion"),
        app_id_match: main_match,
    };

    let mut extensions = Vec::new();
    for extension in application.bundle.app_extensions() {
        let bundle_identifier = extension.bundle_identifier().unwrap_or("").to_string();
        let matched_app_id = app_ids
            .iter()
            .find(|app_id| app_id.identifier == bundle_identifier)
            .cloned();
        let app_id_match = if let Some(app_id) = matched_app_id.as_ref() {
            Some(profile_match(dev_session, team, app_id).await?)
        } else {
            None
        };

        extensions.push(IpaBundleInspection {
            name: extension.bundle_name().unwrap_or("Extension").to_string(),
            bundle_identifier,
            version: plist_string(extension, "CFBundleShortVersionString"),
            build: plist_string(extension, "CFBundleVersion"),
            minimum_os_version: plist_string(extension, "MinimumOSVersion"),
            app_id_match,
        });
    }

    let mut unmatched_bundle_ids = Vec::new();
    if main.app_id_match.is_none() {
        unmatched_bundle_ids.push(main.bundle_identifier.clone());
    }
    for extension in &extensions {
        if extension.app_id_match.is_none() {
            unmatched_bundle_ids.push(extension.bundle_identifier.clone());
        }
    }

    Ok(IpaInspectionResult {
        path: ipa_path,
        main,
        extensions,
        all_bundle_ids_matched: unmatched_bundle_ids.is_empty(),
        unmatched_bundle_ids,
    })
}

#[tauri::command]
pub async fn inspect_ipa_and_match_profiles(
    sideloader_state: State<'_, SideloaderMutex>,
    ipa_path: String,
) -> Result<IpaInspectionResult, AppError> {
    let application = Application::new(PathBuf::from(&ipa_path))?;

    let mut sideloader = SideloaderGuard::take(&sideloader_state)?;
    let team = sideloader.get_mut().get_team().await?;
    let dev_session = sideloader.get_mut().get_dev_session();
    let app_ids = dev_session.list_app_ids(&team, None).await?.app_ids;

    build_inspection(&application, ipa_path, dev_session, &team, &app_ids).await
}

#[tauri::command]
pub async fn preflight_ipa(
    sideloader_state: State<'_, SideloaderMutex>,
    ipa_path: String,
    device_udid: Option<String>,
) -> Result<AutoIpaPreflightReport, AppError> {
    let application = Application::new(PathBuf::from(&ipa_path))?;

    let mut sideloader = SideloaderGuard::take(&sideloader_state)?;
    let team = sideloader.get_mut().get_team().await?;
    let team_id = team.team_id.clone();
    let dev_session = sideloader.get_mut().get_dev_session();

    let certificates = dev_session.list_all_development_certs(&team, None).await?;
    let app_ids = dev_session.list_app_ids(&team, None).await?.app_ids;
    let devices = dev_session.list_devices(&team, None).await?;
    let inspection = build_inspection(&application, ipa_path, dev_session, &team, &app_ids).await?;

    let mut checks = Vec::new();
    checks.push(AutoPreflightCheck {
        code: "certificate.available".into(),
        severity: AutoPreflightSeverity::Error,
        passed: !certificates.is_empty(),
        message: if certificates.is_empty() {
            "No development certificate is available for the selected team.".into()
        } else {
            format!("{} development certificate(s) available.", certificates.len())
        },
    });

    checks.push(AutoPreflightCheck {
        code: "bundle_ids.matched".into(),
        severity: AutoPreflightSeverity::Error,
        passed: inspection.all_bundle_ids_matched,
        message: if inspection.all_bundle_ids_matched {
            "Main app and all extensions have matching App IDs.".into()
        } else {
            format!(
                "Missing matching App IDs for: {}.",
                inspection.unmatched_bundle_ids.join(", ")
            )
        },
    });

    let mut matched_bundles = vec![&inspection.main];
    matched_bundles.extend(inspection.extensions.iter());
    for bundle in matched_bundles {
        if let Some(profile) = bundle.app_id_match.as_ref() {
            let active = profile
                .profile_status
                .as_deref()
                .is_some_and(|status| status.eq_ignore_ascii_case("active"));
            checks.push(AutoPreflightCheck {
                code: format!("profile.active.{}", bundle.bundle_identifier),
                severity: AutoPreflightSeverity::Error,
                passed: active,
                message: if active {
                    format!("Provisioning profile for {} is active.", bundle.bundle_identifier)
                } else {
                    format!(
                        "Provisioning profile for {} is not active.",
                        bundle.bundle_identifier
                    )
                },
            });
        }
    }

    if let Some(udid) = device_udid.as_deref() {
        let registered = devices.iter().any(|device| device.device_number == udid);
        checks.push(AutoPreflightCheck {
            code: "device.registered".into(),
            severity: AutoPreflightSeverity::Error,
            passed: registered,
            message: if registered {
                format!("Device {} is registered on the team.", udid)
            } else {
                format!("Device {} is not registered on the team.", udid)
            },
        });
    } else {
        checks.push(AutoPreflightCheck {
            code: "device.not_requested".into(),
            severity: AutoPreflightSeverity::Info,
            passed: true,
            message: "No target device was supplied for this preflight.".into(),
        });
    }

    let ready = checks
        .iter()
        .filter(|check| matches!(check.severity, AutoPreflightSeverity::Error))
        .all(|check| check.passed);

    Ok(AutoIpaPreflightReport {
        ready,
        team_id,
        inspection,
        checks,
    })
}
