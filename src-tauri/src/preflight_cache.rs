use std::{
    collections::HashMap,
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};

use isideload::dev::{
    app_ids::{AppId, AppIdsApi},
    developer_session::DeveloperSession,
    teams::DeveloperTeam,
};

use crate::error::AppError;

const APP_ID_CACHE_TTL: Duration = Duration::from_secs(60);
const PROFILE_CACHE_TTL: Duration = Duration::from_secs(60);

#[derive(Debug, Clone)]
pub struct AppIdInventory {
    pub app_ids: Vec<AppId>,
    pub max_quantity: Option<u64>,
    pub available_quantity: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct CachedProvisioningProfile {
    pub uuid: String,
    pub name: String,
    pub status: String,
    pub expiration_date: String,
    pub is_free_provisioning_profile: Option<bool>,
    pub encoded_profile: Vec<u8>,
}

#[derive(Debug, Clone)]
struct Timed<T> {
    cached_at: Instant,
    value: T,
}

#[derive(Default)]
struct CacheState {
    app_ids: HashMap<String, Timed<AppIdInventory>>,
    profiles: HashMap<String, Timed<CachedProvisioningProfile>>,
}

static CACHE: OnceLock<Mutex<CacheState>> = OnceLock::new();

fn cache() -> &'static Mutex<CacheState> {
    CACHE.get_or_init(|| Mutex::new(CacheState::default()))
}

fn app_id_key(account_scope: &str, team_id: &str) -> String {
    format!("{account_scope}::{team_id}")
}

fn profile_key(account_scope: &str, team_id: &str, app_id_id: &str) -> String {
    format!("{account_scope}::{team_id}::{app_id_id}")
}

pub async fn app_ids_cached(
    dev_session: &mut DeveloperSession,
    team: &DeveloperTeam,
    account_scope: &str,
    force_refresh: bool,
) -> Result<AppIdInventory, AppError> {
    let key = app_id_key(account_scope, &team.team_id);
    if !force_refresh {
        if let Ok(guard) = cache().lock() {
            if let Some(entry) = guard.app_ids.get(&key) {
                if entry.cached_at.elapsed() < APP_ID_CACHE_TTL {
                    return Ok(entry.value.clone());
                }
            }
        }
    }

    let response = dev_session.list_app_ids(team, None).await?;
    let inventory = AppIdInventory {
        app_ids: response.app_ids,
        max_quantity: response.max_quantity,
        available_quantity: response.available_quantity,
    };

    if let Ok(mut guard) = cache().lock() {
        guard.app_ids.insert(
            key,
            Timed {
                cached_at: Instant::now(),
                value: inventory.clone(),
            },
        );
    }
    Ok(inventory)
}

pub async fn profile_cached(
    dev_session: &mut DeveloperSession,
    team: &DeveloperTeam,
    app_id: &AppId,
    account_scope: &str,
    force_refresh: bool,
) -> Result<CachedProvisioningProfile, AppError> {
    let key = profile_key(account_scope, &team.team_id, &app_id.app_id_id);
    if !force_refresh {
        if let Ok(guard) = cache().lock() {
            if let Some(entry) = guard.profiles.get(&key) {
                if entry.cached_at.elapsed() < PROFILE_CACHE_TTL {
                    return Ok(entry.value.clone());
                }
            }
        }
    }

    let profile = dev_session
        .download_team_provisioning_profile(team, app_id, None)
        .await?;
    let cached = CachedProvisioningProfile {
        uuid: profile.uuid,
        name: profile.name,
        status: profile.status,
        expiration_date: format!("{:?}", profile.date_expire),
        is_free_provisioning_profile: profile.is_free_provisioning_profile,
        encoded_profile: profile.encoded_profile.as_ref().to_vec(),
    };

    if let Ok(mut guard) = cache().lock() {
        guard.profiles.insert(
            key,
            Timed {
                cached_at: Instant::now(),
                value: cached.clone(),
            },
        );
    }
    Ok(cached)
}

pub fn invalidate_team(account_scope: &str, team_id: &str) {
    let prefix = format!("{account_scope}::{team_id}");
    if let Ok(mut guard) = cache().lock() {
        guard.app_ids.remove(&prefix);
        guard.profiles.retain(|key, _| !key.starts_with(&format!("{prefix}::")));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn team_invalidation_is_account_scoped() {
        let account_a = "a@example.com";
        let account_b = "b@example.com";
        let team = "TEAM1";
        let a_key = app_id_key(account_a, team);
        let b_key = app_id_key(account_b, team);

        {
            let mut guard = cache().lock().unwrap();
            guard.app_ids.clear();
            guard.app_ids.insert(
                a_key.clone(),
                Timed {
                    cached_at: Instant::now(),
                    value: AppIdInventory {
                        app_ids: vec![],
                        max_quantity: Some(10),
                        available_quantity: Some(5),
                    },
                },
            );
            guard.app_ids.insert(
                b_key.clone(),
                Timed {
                    cached_at: Instant::now(),
                    value: AppIdInventory {
                        app_ids: vec![],
                        max_quantity: Some(10),
                        available_quantity: Some(4),
                    },
                },
            );
        }

        invalidate_team(account_a, team);
        let guard = cache().lock().unwrap();
        assert!(!guard.app_ids.contains_key(&a_key));
        assert!(guard.app_ids.contains_key(&b_key));
    }
}
