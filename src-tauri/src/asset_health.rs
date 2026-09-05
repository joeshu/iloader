use std::{
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};

use chrono::Utc;
use isideload::dev::{
    app_ids::AppIdsApi,
    certificates::CertificatesApi,
    devices::DevicesApi,
};
use serde::Serialize;
use tauri::State;

use crate::{
    error::AppError,
    sideload::{SideloaderGuard, SideloaderMutex},
};

const ASSET_HEALTH_TTL: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum AssetHealthStatus {
    Healthy,
    Warning,
    Error,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AssetHealthCheck {
    pub code: String,
    pub status: AssetHealthStatus,
    pub title: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SigningAssetHealthReport {
    pub generated_at_utc: String,
    pub cached: bool,
    pub cache_ttl_seconds: u64,
    pub team_id: String,
    pub email: String,
    pub overall_status: AssetHealthStatus,
    pub certificate_count: usize,
    pub app_id_count: usize,
    pub device_count: usize,
    pub max_app_ids: Option<u64>,
    pub available_app_ids: Option<i64>,
    pub checks: Vec<AssetHealthCheck>,
}

#[derive(Debug, Clone)]
struct CachedAssetHealth {
    cached_at: Instant,
    report: SigningAssetHealthReport,
}

static ASSET_HEALTH_CACHE: OnceLock<Mutex<Option<CachedAssetHealth>>> = OnceLock::new();

fn cache() -> &'static Mutex<Option<CachedAssetHealth>> {
    ASSET_HEALTH_CACHE.get_or_init(|| Mutex::new(None))
}

fn status_rank(status: AssetHealthStatus) -> u8 {
    match status {
        AssetHealthStatus::Healthy => 0,
        AssetHealthStatus::Warning => 1,
        AssetHealthStatus::Error => 2,
    }
}

fn overall_status(checks: &[AssetHealthCheck]) -> AssetHealthStatus {
    checks
        .iter()
        .map(|check| check.status)
        .max_by_key(|status| status_rank(*status))
        .unwrap_or(AssetHealthStatus::Healthy)
}

fn cached_report(email: &str, team_id: &str) -> Option<SigningAssetHealthReport> {
    let guard = cache().lock().ok()?;
    let cached = guard.as_ref()?;
    if cached.cached_at.elapsed() >= ASSET_HEALTH_TTL
        || cached.report.email != email
        || cached.report.team_id != team_id
    {
        return None;
    }

    let mut report = cached.report.clone();
    report.cached = true;
    Some(report)
}

fn update_cache(report: &SigningAssetHealthReport) {
    if let Ok(mut guard) = cache().lock() {
        *guard = Some(CachedAssetHealth {
            cached_at: Instant::now(),
            report: report.clone(),
        });
    }
}

fn check(
    code: &str,
    status: AssetHealthStatus,
    title: &str,
    message: impl Into<String>,
) -> AssetHealthCheck {
    AssetHealthCheck {
        code: code.into(),
        status,
        title: title.into(),
        message: message.into(),
    }
}

#[tauri::command]
pub async fn get_signing_asset_health(
    sideloader_state: State<'_, SideloaderMutex>,
    force_refresh: Option<bool>,
) -> Result<SigningAssetHealthReport, AppError> {
    let mut sideloader = SideloaderGuard::take(&sideloader_state)?;
    let email = sideloader.get_mut().get_email().to_string();
    let team = sideloader.get_mut().get_team().await?;
    let team_id = team.team_id.clone();

    if !force_refresh.unwrap_or(false) {
        if let Some(report) = cached_report(&email, &team_id) {
            return Ok(report);
        }
    }

    let dev_session = sideloader.get_mut().get_dev_session();
    let certificates = dev_session.list_all_development_certs(&team, None).await?;
    let app_ids = dev_session.list_app_ids(&team, None).await?;
    let devices = dev_session.list_devices(&team, None).await?;

    let certificate_count = certificates.len();
    let app_id_count = app_ids.app_ids.len();
    let device_count = devices.len();

    let mut checks = Vec::with_capacity(4);
    checks.push(if certificate_count == 0 {
        check(
            "certificate.available",
            AssetHealthStatus::Error,
            "Development certificate",
            "No development certificate is available for this team.",
        )
    } else {
        check(
            "certificate.available",
            AssetHealthStatus::Healthy,
            "Development certificate",
            format!("{certificate_count} development certificate(s) available."),
        )
    });

    checks.push(match app_ids.available_quantity {
        Some(value) if value <= 0 => check(
            "app_ids.capacity",
            AssetHealthStatus::Error,
            "App ID capacity",
            "No App ID registration slots are currently available.",
        ),
        Some(1) => check(
            "app_ids.capacity",
            AssetHealthStatus::Warning,
            "App ID capacity",
            "Only one App ID registration slot remains.",
        ),
        Some(value) => check(
            "app_ids.capacity",
            AssetHealthStatus::Healthy,
            "App ID capacity",
            format!("{value} App ID registration slots remain."),
        ),
        None => check(
            "app_ids.capacity",
            AssetHealthStatus::Warning,
            "App ID capacity",
            "Apple did not return App ID quota information for this team.",
        ),
    });

    checks.push(if app_id_count == 0 {
        check(
            "app_ids.available",
            AssetHealthStatus::Warning,
            "Registered App IDs",
            "No App IDs are currently registered. The first signing operation may need to create them.",
        )
    } else {
        check(
            "app_ids.available",
            AssetHealthStatus::Healthy,
            "Registered App IDs",
            format!("{app_id_count} App ID(s) are registered."),
        )
    });

    checks.push(if device_count == 0 {
        check(
            "devices.available",
            AssetHealthStatus::Warning,
            "Registered devices",
            "No devices are registered on this developer team.",
        )
    } else {
        check(
            "devices.available",
            AssetHealthStatus::Healthy,
            "Registered devices",
            format!("{device_count} device(s) are registered."),
        )
    });

    let report = SigningAssetHealthReport {
        generated_at_utc: Utc::now().to_rfc3339(),
        cached: false,
        cache_ttl_seconds: ASSET_HEALTH_TTL.as_secs(),
        team_id,
        email,
        overall_status: overall_status(&checks),
        certificate_count,
        app_id_count,
        device_count,
        max_app_ids: app_ids.max_quantity,
        available_app_ids: app_ids.available_quantity,
        checks,
    };

    update_cache(&report);
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overall_status_uses_most_severe_check() {
        let checks = vec![
            check("a", AssetHealthStatus::Healthy, "a", "ok"),
            check("b", AssetHealthStatus::Warning, "b", "warn"),
            check("c", AssetHealthStatus::Error, "c", "error"),
        ];
        assert_eq!(overall_status(&checks), AssetHealthStatus::Error);
    }
}
