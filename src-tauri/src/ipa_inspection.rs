use std::path::PathBuf;

use isideload::{
    dev::app_ids::{AppId, AppIdsApi},
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

    let main_bundle_id = application.main_bundle_id()?;
    let main_app_id = app_ids
        .iter()
        .find(|app_id| app_id.identifier == main_bundle_id)
        .cloned();
    let main_match = if let Some(app_id) = main_app_id.as_ref() {
        Some(profile_match(dev_session, &team, app_id).await?)
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
            Some(profile_match(dev_session, &team, app_id).await?)
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
