use std::{collections::HashSet, path::PathBuf};

use isideload::{
    dev::{
        app_ids::{AppId, AppIdsApi},
        certificates::CertificatesApi,
        devices::DevicesApi,
    },
    sideload::application::Application,
};
use serde::Serialize;
use tauri::{Emitter, State, Window};

use crate::{
    entitlement_compatibility::{
        EntitlementCompatibilityReport, build_entitlement_compatibility,
    },
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
    pub signing_bundle_identifier: String,
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
    pub requires_registration_bundle_ids: Vec<String>,
    pub extension_bundle_ids_valid: bool,
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
    pub entitlements: EntitlementCompatibilityReport,
    pub checks: Vec<AutoPreflightCheck>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchIpaPreflightItem {
    pub input_path: String,
    pub report: Option<AutoIpaPreflightReport>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchIpaPreflightReport {
    pub total: usize,
    pub ready: usize,
    pub blocked: usize,
    pub failed: usize,
    pub items: Vec<BatchIpaPreflightItem>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchIpaPreflightProgress {
    pub input_path: String,
    pub stage: String,
    pub ready: Option<bool>,
    pub error: Option<String>,
}

fn emit_batch_preflight_progress(
    window: &Window,
    input_path: &str,
    stage: &str,
    ready: Option<bool>,
    error: Option<String>,
) {
    if let Err(error) = window.emit(
        "batch_preflight_progress",
        BatchIpaPreflightProgress {
            input_path: input_path.to_string(),
            stage: stage.to_string(),
            ready,
            error,
        },
    ) {
        tracing::warn!("Failed to emit batch preflight progress event: {}", error);
    }
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
    let signing_main_bundle_id = format!("{}.{}", main_bundle_id, team.team_id);
    let main_app_id = app_ids
        .iter()
        .find(|app_id| app_id.identifier == signing_main_bundle_id)
        .cloned();
    let main_match = if let Some(app_id) = main_app_id.as_ref() {
        Some(profile_match(dev_session, team, app_id).await?)
    } else {
        None
    };

    let main = IpaBundleInspection {
        name: application.main_app_name()?,
        bundle_identifier: main_bundle_id.clone(),
        signing_bundle_identifier: signing_main_bundle_id.clone(),
        version: plist_string(&application.bundle, "CFBundleShortVersionString"),
        build: plist_string(&application.bundle, "CFBundleVersion"),
        minimum_os_version: plist_string(&application.bundle, "MinimumOSVersion"),
        app_id_match: main_match,
    };

    let mut extensions = Vec::new();
    let mut extension_bundle_ids_valid = true;
    for extension in application.bundle.app_extensions() {
        let bundle_identifier = extension.bundle_identifier().unwrap_or("").to_string();
        let signing_bundle_identifier = if bundle_identifier.starts_with(&main_bundle_id)
            && bundle_identifier.len() > main_bundle_id.len()
        {
            format!(
                "{}{}",
                signing_main_bundle_id,
                &bundle_identifier[main_bundle_id.len()..]
            )
        } else {
            extension_bundle_ids_valid = false;
            bundle_identifier.clone()
        };

        let matched_app_id = app_ids
            .iter()
            .find(|app_id| app_id.identifier == signing_bundle_identifier)
            .cloned();
        let app_id_match = if let Some(app_id) = matched_app_id.as_ref() {
            Some(profile_match(dev_session, team, app_id).await?)
        } else {
            None
        };

        extensions.push(IpaBundleInspection {
            name: extension.bundle_name().unwrap_or("Extension").to_string(),
            bundle_identifier,
            signing_bundle_identifier,
            version: plist_string(extension, "CFBundleShortVersionString"),
            build: plist_string(extension, "CFBundleVersion"),
            minimum_os_version: plist_string(extension, "MinimumOSVersion"),
            app_id_match,
        });
    }

    let mut unmatched_bundle_ids = Vec::new();
    if main.app_id_match.is_none() {
        unmatched_bundle_ids.push(main.signing_bundle_identifier.clone());
    }
    for extension in &extensions {
        if extension.app_id_match.is_none() {
            unmatched_bundle_ids.push(extension.signing_bundle_identifier.clone());
        }
    }

    Ok(IpaInspectionResult {
        path: ipa_path,
        main,
        extensions,
        all_bundle_ids_matched: unmatched_bundle_ids.is_empty(),
        requires_registration_bundle_ids: unmatched_bundle_ids.clone(),
        unmatched_bundle_ids,
        extension_bundle_ids_valid,
    })
}

fn build_preflight_report(
    team_id: &str,
    inspection: IpaInspectionResult,
    entitlements: EntitlementCompatibilityReport,
    certificate_count: usize,
    available_app_ids: Option<i64>,
    device_udid: Option<&str>,
    device_registered: Option<bool>,
) -> AutoIpaPreflightReport {
    let mut checks = Vec::new();
    checks.push(AutoPreflightCheck {
        code: "certificate.available".into(),
        severity: AutoPreflightSeverity::Error,
        passed: certificate_count > 0,
        message: if certificate_count == 0 {
            "No development certificate is available for the selected team.".into()
        } else {
            format!("{} development certificate(s) available.", certificate_count)
        },
    });

    checks.push(AutoPreflightCheck {
        code: "extensions.bundle_id_relationship".into(),
        severity: AutoPreflightSeverity::Error,
        passed: inspection.extension_bundle_ids_valid,
        message: if inspection.extension_bundle_ids_valid {
            "All extension bundle identifiers are derived from the main bundle identifier.".into()
        } else {
            "At least one extension bundle identifier is not derived from the main bundle identifier and the current signing engine cannot rewrite it safely.".into()
        },
    });

    let registrations_needed = inspection.requires_registration_bundle_ids.len();
    if registrations_needed == 0 {
        checks.push(AutoPreflightCheck {
            code: "app_ids.ready".into(),
            severity: AutoPreflightSeverity::Info,
            passed: true,
            message: "All signing App IDs already exist on the developer team.".into(),
        });
    } else {
        checks.push(AutoPreflightCheck {
            code: "app_ids.registration_required".into(),
            severity: AutoPreflightSeverity::Warning,
            passed: true,
            message: format!(
                "{} App ID(s) will be registered automatically during signing: {}.",
                registrations_needed,
                inspection.requires_registration_bundle_ids.join(", ")
            ),
        });

        if let Some(available) = available_app_ids {
            let enough = available < 0 || registrations_needed <= available as usize;
            checks.push(AutoPreflightCheck {
                code: "app_ids.capacity".into(),
                severity: AutoPreflightSeverity::Error,
                passed: enough,
                message: if available < 0 {
                    format!(
                        "Apple reported an invalid negative App ID quota ({}); signing will still attempt registration.",
                        available
                    )
                } else if enough {
                    format!(
                        "{} App ID slot(s) are available; {} are required.",
                        available, registrations_needed
                    )
                } else {
                    format!(
                        "Not enough App ID slots: {} available, {} required.",
                        available, registrations_needed
                    )
                },
            });
        } else {
            checks.push(AutoPreflightCheck {
                code: "app_ids.capacity_unknown".into(),
                severity: AutoPreflightSeverity::Warning,
                passed: true,
                message: "Apple did not report an App ID quota; registration capacity will be verified during signing.".into(),
            });
        }
    }

    let mut matched_bundles = vec![&inspection.main];
    matched_bundles.extend(inspection.extensions.iter());
    for bundle in matched_bundles {
        if let Some(profile) = bundle.app_id_match.as_ref() {
            let active = profile
                .profile_status
                .as_deref()
                .is_some_and(|status| status.eq_ignore_ascii_case("active"));
            checks.push(AutoPreflightCheck {
                code: format!("profile.active.{}", bundle.signing_bundle_identifier),
                severity: AutoPreflightSeverity::Error,
                passed: active,
                message: if active {
                    format!(
                        "Provisioning profile for {} is active.",
                        bundle.signing_bundle_identifier
                    )
                } else {
                    format!(
                        "Provisioning profile for {} is not active.",
                        bundle.signing_bundle_identifier
                    )
                },
            });
        } else {
            checks.push(AutoPreflightCheck {
                code: format!("profile.pending.{}", bundle.signing_bundle_identifier),
                severity: AutoPreflightSeverity::Info,
                passed: true,
                message: format!(
                    "Provisioning profile for {} will be created after its App ID is registered.",
                    bundle.signing_bundle_identifier
                ),
            });
        }
    }

    checks.push(AutoPreflightCheck {
        code: "entitlements.compatibility".into(),
        severity: if entitlements.blocking_count > 0 {
            AutoPreflightSeverity::Error
        } else if entitlements.warning_count > 0 {
            AutoPreflightSeverity::Warning
        } else {
            AutoPreflightSeverity::Info
        },
        passed: entitlements.blocking_count == 0,
        message: if entitlements.blocking_count > 0 {
            format!(
                "Entitlement compatibility found {} blocking issue(s) and {} warning(s).",
                entitlements.blocking_count, entitlements.warning_count
            )
        } else if entitlements.warning_count > 0 {
            format!(
                "Entitlement compatibility found no blocking issues and {} warning(s).",
                entitlements.warning_count
            )
        } else {
            "Entitlement compatibility found no blocking issues or warnings.".into()
        },
    });

    if let Some(udid) = device_udid {
        let registered = device_registered.unwrap_or(false);
        checks.push(AutoPreflightCheck {
            code: "device.registered".into(),
            severity: AutoPreflightSeverity::Warning,
            passed: true,
            message: if registered {
                format!("Device {} is already registered on the team.", udid)
            } else {
                format!(
                    "Device {} is not registered yet; installation flow can register it automatically.",
                    udid
                )
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

    AutoIpaPreflightReport {
        ready,
        team_id: team_id.to_string(),
        inspection,
        entitlements,
        checks,
    }
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
    let app_ids_response = dev_session.list_app_ids(&team, None).await?;
    let available_app_ids = app_ids_response.available_quantity;
    let app_ids = app_ids_response.app_ids;
    let devices = dev_session.list_devices(&team, None).await?;
    let device_registered = device_udid
        .as_deref()
        .map(|udid| devices.iter().any(|device| device.device_number == udid));
    let inspection = build_inspection(
        &application,
        ipa_path,
        dev_session,
        &team,
        &app_ids,
    )
    .await?;
    let entitlements = build_entitlement_compatibility(
        &application,
        dev_session,
        &team,
        &app_ids,
    )
    .await?;

    Ok(build_preflight_report(
        &team_id,
        inspection,
        entitlements,
        certificates.len(),
        available_app_ids,
        device_udid.as_deref(),
        device_registered,
    ))
}

#[tauri::command]
pub async fn preflight_ipas(
    window: Window,
    sideloader_state: State<'_, SideloaderMutex>,
    ipa_paths: Vec<String>,
    device_udid: Option<String>,
) -> Result<BatchIpaPreflightReport, AppError> {
    let mut sideloader = SideloaderGuard::take(&sideloader_state)?;
    let team = sideloader.get_mut().get_team().await?;
    let team_id = team.team_id.clone();
    let dev_session = sideloader.get_mut().get_dev_session();

    let certificates = dev_session.list_all_development_certs(&team, None).await?;
    let app_ids_response = dev_session.list_app_ids(&team, None).await?;
    let available_app_ids = app_ids_response.available_quantity;
    let app_ids = app_ids_response.app_ids;
    let devices = dev_session.list_devices(&team, None).await?;
    let device_registered = device_udid
        .as_deref()
        .map(|udid| devices.iter().any(|device| device.device_number == udid));

    let mut items = Vec::with_capacity(ipa_paths.len());
    for ipa_path in ipa_paths {
        emit_batch_preflight_progress(&window, &ipa_path, "scanning", None, None);

        let application = match Application::new(PathBuf::from(&ipa_path)) {
            Ok(application) => application,
            Err(error) => {
                let message = format!("Failed to inspect IPA: {error:?}");
                emit_batch_preflight_progress(
                    &window,
                    &ipa_path,
                    "failed",
                    Some(false),
                    Some(message.clone()),
                );
                items.push(BatchIpaPreflightItem {
                    input_path: ipa_path,
                    report: None,
                    error: Some(message),
                });
                continue;
            }
        };

        let inspection = match build_inspection(
            &application,
            ipa_path.clone(),
            dev_session,
            &team,
            &app_ids,
        )
        .await
        {
            Ok(inspection) => inspection,
            Err(error) => {
                let message = format!("Preflight failed: {error:?}");
                emit_batch_preflight_progress(
                    &window,
                    &ipa_path,
                    "failed",
                    Some(false),
                    Some(message.clone()),
                );
                items.push(BatchIpaPreflightItem {
                    input_path: ipa_path,
                    report: None,
                    error: Some(message),
                });
                continue;
            }
        };

        let entitlements = match build_entitlement_compatibility(
            &application,
            dev_session,
            &team,
            &app_ids,
        )
        .await
        {
            Ok(report) => report,
            Err(error) => {
                let message = format!("Entitlement preflight failed: {error:?}");
                emit_batch_preflight_progress(
                    &window,
                    &ipa_path,
                    "failed",
                    Some(false),
                    Some(message.clone()),
                );
                items.push(BatchIpaPreflightItem {
                    input_path: ipa_path,
                    report: None,
                    error: Some(message),
                });
                continue;
            }
        };

        let report = build_preflight_report(
            &team_id,
            inspection,
            entitlements,
            certificates.len(),
            available_app_ids,
            device_udid.as_deref(),
            device_registered,
        );
        emit_batch_preflight_progress(
            &window,
            &ipa_path,
            if report.ready { "ready" } else { "blocked" },
            Some(report.ready),
            None,
        );
        items.push(BatchIpaPreflightItem {
            input_path: ipa_path,
            report: Some(report),
            error: None,
        });
    }

    if let Some(available) = available_app_ids.filter(|available| *available >= 0) {
        let mut remaining = available as usize;
        let mut planned_registrations = HashSet::<String>::new();

        for item in &mut items {
            let input_path = item.input_path.clone();
            let mut capacity_blocked = false;

            if let Some(report) = item.report.as_mut()
                && report.ready
            {
                let needed = report
                    .inspection
                    .requires_registration_bundle_ids
                    .iter()
                    .filter(|identifier| !planned_registrations.contains(*identifier))
                    .cloned()
                    .collect::<Vec<_>>();

                if needed.len() > remaining {
                    report.checks.push(AutoPreflightCheck {
                        code: "batch.app_ids.capacity".into(),
                        severity: AutoPreflightSeverity::Error,
                        passed: false,
                        message: format!(
                            "Batch App ID quota exhausted before this IPA: {} slot(s) remain, {} additional App ID(s) are required.",
                            remaining,
                            needed.len()
                        ),
                    });
                    report.ready = false;
                    capacity_blocked = true;
                } else {
                    remaining -= needed.len();
                    planned_registrations.extend(needed);
                }
            }

            if capacity_blocked {
                emit_batch_preflight_progress(
                    &window,
                    &input_path,
                    "blocked",
                    Some(false),
                    Some("Batch App ID quota is insufficient for this queue position.".into()),
                );
            }
        }
    }

    let ready = items
        .iter()
        .filter(|item| item.report.as_ref().is_some_and(|report| report.ready))
        .count();
    let failed = items.iter().filter(|item| item.report.is_none()).count();
    let blocked = items.len().saturating_sub(ready + failed);

    Ok(BatchIpaPreflightReport {
        total: items.len(),
        ready,
        blocked,
        failed,
        items,
    })
}
