use isideload::dev::{
    app_ids::AppIdsApi,
    certificates::CertificatesApi,
    devices::DevicesApi,
};
use serde::{Deserialize, Serialize};
use tauri::State;

use crate::{
    error::AppError,
    sideload::{SideloaderGuard, SideloaderMutex},
};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SigningCenterCertificate {
    pub name: Option<String>,
    pub certificate_id: Option<String>,
    pub serial_number: Option<String>,
    pub machine_name: Option<String>,
    pub machine_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SigningCenterAppId {
    pub app_id_id: String,
    pub identifier: String,
    pub name: String,
    pub feature_keys: Vec<String>,
    pub expiration_date: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SigningCenterDevice {
    pub name: Option<String>,
    pub device_id: Option<String>,
    pub udid: String,
    pub status: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SigningCenterSnapshot {
    pub email: String,
    pub team_id: String,
    pub certificates: Vec<SigningCenterCertificate>,
    pub app_ids: Vec<SigningCenterAppId>,
    pub devices: Vec<SigningCenterDevice>,
    pub max_app_ids: Option<u64>,
    pub available_app_ids: Option<i64>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreflightRequest {
    pub app_id_id: String,
    pub bundle_identifier: String,
    pub device_udid: Option<String>,
    #[serde(default)]
    pub required_capabilities: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreflightCheck {
    pub code: String,
    pub severity: PreflightSeverity,
    pub passed: bool,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum PreflightSeverity {
    Info,
    Warning,
    Error,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreflightProfileInfo {
    pub uuid: String,
    pub name: String,
    pub status: String,
    pub distribution_method: String,
    pub expiration_date: String,
    pub is_free_provisioning_profile: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreflightReport {
    pub ready: bool,
    pub team_id: String,
    pub app_identifier: String,
    pub profile: Option<PreflightProfileInfo>,
    pub checks: Vec<PreflightCheck>,
}

#[tauri::command]
pub async fn get_signing_center_snapshot(
    sideloader_state: State<'_, SideloaderMutex>,
) -> Result<SigningCenterSnapshot, AppError> {
    let mut sideloader = SideloaderGuard::take(&sideloader_state)?;
    let email = sideloader.get_mut().get_email().to_string();
    let team = sideloader.get_mut().get_team().await?;
    let team_id = team.team_id.clone();
    let dev_session = sideloader.get_mut().get_dev_session();

    let certificates = dev_session.list_all_development_certs(&team, None).await?;
    let app_ids = dev_session.list_app_ids(&team, None).await?;
    let devices = dev_session.list_devices(&team, None).await?;

    Ok(SigningCenterSnapshot {
        email,
        team_id,
        certificates: certificates
            .into_iter()
            .map(|cert| SigningCenterCertificate {
                name: cert.name,
                certificate_id: cert.certificate_id,
                serial_number: cert.serial_number,
                machine_name: cert.machine_name,
                machine_id: cert.machine_id,
            })
            .collect(),
        app_ids: app_ids
            .app_ids
            .into_iter()
            .map(|app_id| SigningCenterAppId {
                app_id_id: app_id.app_id_id,
                identifier: app_id.identifier,
                name: app_id.name,
                feature_keys: app_id.features.keys().cloned().collect(),
                expiration_date: app_id.expiration_date.map(|value| format!("{:?}", value)),
            })
            .collect(),
        devices: devices
            .into_iter()
            .map(|device| SigningCenterDevice {
                name: device.name,
                device_id: device.device_id,
                udid: device.device_number,
                status: device.status,
            })
            .collect(),
        max_app_ids: app_ids.max_quantity,
        available_app_ids: app_ids.available_quantity,
    })
}

#[tauri::command]
pub async fn preflight_signing(
    sideloader_state: State<'_, SideloaderMutex>,
    request: PreflightRequest,
) -> Result<PreflightReport, AppError> {
    let mut sideloader = SideloaderGuard::take(&sideloader_state)?;
    let team = sideloader.get_mut().get_team().await?;
    let team_id = team.team_id.clone();
    let dev_session = sideloader.get_mut().get_dev_session();

    let certificates = dev_session.list_all_development_certs(&team, None).await?;
    let app_ids_response = dev_session.list_app_ids(&team, None).await?;
    let devices = dev_session.list_devices(&team, None).await?;

    let mut checks = Vec::new();

    checks.push(PreflightCheck {
        code: "certificate.available".into(),
        severity: PreflightSeverity::Error,
        passed: !certificates.is_empty(),
        message: if certificates.is_empty() {
            "No development certificate is available for the selected team.".into()
        } else {
            format!("{} development certificate(s) available.", certificates.len())
        },
    });

    let selected_app = app_ids_response
        .app_ids
        .iter()
        .find(|app_id| app_id.app_id_id == request.app_id_id);

    let Some(app_id) = selected_app else {
        checks.push(PreflightCheck {
            code: "app_id.exists".into(),
            severity: PreflightSeverity::Error,
            passed: false,
            message: "Selected App ID no longer exists on the Apple developer team.".into(),
        });
        return Ok(PreflightReport {
            ready: false,
            team_id,
            app_identifier: request.bundle_identifier,
            profile: None,
            checks,
        });
    };

    checks.push(PreflightCheck {
        code: "app_id.exists".into(),
        severity: PreflightSeverity::Info,
        passed: true,
        message: format!("App ID {} is available.", app_id.identifier),
    });

    let bundle_matches = app_id.identifier == request.bundle_identifier;
    checks.push(PreflightCheck {
        code: "bundle_id.matches".into(),
        severity: PreflightSeverity::Error,
        passed: bundle_matches,
        message: if bundle_matches {
            "Bundle identifier matches the selected App ID.".into()
        } else {
            format!(
                "Bundle identifier mismatch: IPA uses {}, selected App ID uses {}.",
                request.bundle_identifier, app_id.identifier
            )
        },
    });

    if let Some(udid) = request.device_udid.as_deref() {
        let registered = devices.iter().any(|device| device.device_number == udid);
        checks.push(PreflightCheck {
            code: "device.registered".into(),
            severity: PreflightSeverity::Error,
            passed: registered,
            message: if registered {
                format!("Device {} is registered on the team.", udid)
            } else {
                format!("Device {} is not registered on the team.", udid)
            },
        });
    } else {
        checks.push(PreflightCheck {
            code: "device.not_requested".into(),
            severity: PreflightSeverity::Info,
            passed: true,
            message: "No target device was supplied for this preflight.".into(),
        });
    }

    for capability in &request.required_capabilities {
        let present = app_id.features.contains_key(capability);
        checks.push(PreflightCheck {
            code: format!("capability.{}", capability),
            severity: PreflightSeverity::Warning,
            passed: present,
            message: if present {
                format!("Capability {} is present on the App ID.", capability)
            } else {
                format!("Capability {} is not present on the App ID.", capability)
            },
        });
    }

    let profile = dev_session
        .download_team_provisioning_profile(&team, app_id, None)
        .await?;

    let profile_active = profile.status.eq_ignore_ascii_case("active");
    checks.push(PreflightCheck {
        code: "profile.active".into(),
        severity: PreflightSeverity::Error,
        passed: profile_active,
        message: if profile_active {
            "Provisioning profile is active.".into()
        } else {
            format!("Provisioning profile status is {}.", profile.status)
        },
    });

    let ready = checks
        .iter()
        .filter(|check| matches!(check.severity, PreflightSeverity::Error))
        .all(|check| check.passed);

    Ok(PreflightReport {
        ready,
        team_id,
        app_identifier: app_id.identifier.clone(),
        profile: Some(PreflightProfileInfo {
            uuid: profile.uuid,
            name: profile.name,
            status: profile.status,
            distribution_method: profile.distribution_method,
            expiration_date: format!("{:?}", profile.date_expire),
            is_free_provisioning_profile: profile.is_free_provisioning_profile,
        }),
        checks,
    })
}
