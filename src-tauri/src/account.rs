use futures::FutureExt;
use isideload::{
    anisette::remote_v3::RemoteV3AnisetteProvider,
    auth::apple_account::{AppleAccount, TwoFactorCallbackParams, TwoFactorCallbackResponse},
    dev::{app_ids::{AppIdsApi, ListAppIdsResponse}, certificates::{CertificatesApi, DevelopmentCertificate}, developer_session::DeveloperSession},
    sideload::{SideloaderBuilder, builder::MaxCertsBehavior, sideloader::Sideloader},
};
use keyring::Entry;
use rootcause::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::Duration;
use tauri::{AppHandle, Emitter, Listener, State, Window};
use tauri_plugin_dialog::DialogExt;
use tauri_plugin_store::StoreExt;
use tracing::debug;
use crate::{error::AppError, secure_storage::create_sideloading_storage, sideload::{SideloaderGuard, SideloaderMutex}};

#[tauri::command]
pub async fn login_new(handle: AppHandle, window: Window, sideloader_state: State<'_, SideloaderMutex>, email: String, password: String, anisette_server: String, save_credentials: bool) -> Result<(), AppError> {
    let account = login(&handle, &window, &email, &password, anisette_server).await?;
    *sideloader_state.lock().unwrap() = Some(account);
    if save_credentials { let e=Entry::new("iloader",&email).map_err(|e|AppError::KeyringWithMessage("Failed to create entry for credentials".into(),e.to_string()))?; e.set_password(&password).map_err(|e|AppError::KeyringWithMessage("Failed to save credentials".into(),e.to_string()))?; let store=handle.store("data.json").map_err(|e|AppError::Misc(format!("Failed to get store: {:?}",e)))?; let mut ids=store.get("ids").unwrap_or_else(||Value::Array(vec![])).as_array().cloned().unwrap_or_default(); let v=Value::String(email);if !ids.contains(&v){ids.push(v)}store.set("ids",Value::Array(ids)); } Ok(())
}
#[tauri::command] pub async fn login_stored(handle:AppHandle,window:Window,email:String,anisette_server:String,sideloader_state:State<'_,SideloaderMutex>)->Result<(),AppError>{let e=Entry::new("iloader",&email).map_err(|e|AppError::KeyringWithMessage("Failed to create keyring entry for credentials".into(),e.to_string()))?;let p=e.get_password().map_err(|e|AppError::KeyringWithMessage("Failed to get credentials".into(),e.to_string()))?;*sideloader_state.lock().unwrap()=Some(login(&handle,&window,&email,&p,anisette_server).await?);Ok(())}
#[tauri::command] pub fn delete_account(handle:AppHandle,email:String)->Result<(),AppError>{let store=handle.store("data.json").map_err(|e|AppError::Misc(format!("Failed to get store: {:?}",e)))?;let mut ids=store.get("ids").unwrap_or_else(||Value::Array(vec![])).as_array().cloned().unwrap_or_default();ids.retain(|v|v.as_str().is_none_or(|s|s!=email));store.set("ids",Value::Array(ids));Entry::new("iloader",&email).map_err(|e|AppError::KeyringWithMessage("Failed to create keyring entry for credentials".into(),e.to_string()))?.delete_credential().map_err(|e|AppError::KeyringWithMessage("Failed to delete credentials".into(),e.to_string()))?;Ok(())}
#[tauri::command] pub fn logged_in_as(s:State<'_,SideloaderMutex>)->Option<String>{s.lock().unwrap().as_ref().map(|a|a.get_email().to_string())}
#[tauri::command] pub fn invalidate_account(s:State<'_,SideloaderMutex>){*s.lock().unwrap()=None}
#[tauri::command] pub fn reset_anisette_state()->Result<bool,AppError>{let e=Entry::new("iloader","anisette_state").map_err(|e|AppError::KeyringWithMessage("Failed to create keyring entry for anisette".into(),e.to_string()))?;match e.delete_credential(){Ok(_)=>Ok(true),Err(keyring::Error::NoEntry)=>Ok(false),Err(e)=>Err(AppError::KeyringWithMessage("Failed to delete anisette state".into(),e.to_string()))}}

async fn login(app:&AppHandle,window:&Window,email:&str,password:&str,anisette_server:String)->Result<Sideloader,AppError>{
 let cb={let w=window.clone();move|params:TwoFactorCallbackParams|{let w=w.clone();async move{w.emit("2fa-required",params).context("Failed to emit 2fa-required event")?;let(tx,rx)=std::sync::mpsc::channel::<String>();let id=w.listen("2fa-recieved",move|e|{let _=tx.send(e.payload().to_string());});let r=rx.recv_timeout(Duration::from_secs(120))?;w.unlisten(id);Ok(TwoFactorCallbackResponse::SubmitCode(r.trim_matches('"').to_string()))}.boxed()}};
 let url=if anisette_server.starts_with("http"){anisette_server}else{format!("https://{}",anisette_server)};let mut a=AppleAccount::builder(&email.to_lowercase()).anisette_provider(RemoteV3AnisetteProvider::default()?.set_serial_number("0".into()).set_storage(create_sideloading_storage(app)?).set_url(&url)).login(password,Box::new(cb)).await?;debug!("Logged in");let ds=DeveloperSession::from_account(&mut a).await?;
 let maxcb={let w=window.clone();move|certs:&Vec<DevelopmentCertificate>|->Option<Vec<String>>{let infos:Vec<CertificateInfo>=certs.iter().map(|c|CertificateInfo{name:c.name.clone(),certificate_id:c.certificate_id.clone(),serial_number:c.serial_number.clone(),machine_name:c.machine_name.clone(),machine_id:c.machine_id.clone()}).collect();w.emit("max-certs-reached",infos).ok()?;let(tx,rx)=std::sync::mpsc::channel();let id=w.listen("max-certs-response",move|e|{let _=tx.send(serde_json::from_str::<Option<Vec<String>>>(e.payload()).unwrap_or(None));});let r=rx.recv_timeout(Duration::from_secs(300)).ok().flatten();w.unlisten(id);r}};
 Ok(SideloaderBuilder::new(ds,email.to_lowercase()).machine_name("iloader".into()).storage(create_sideloading_storage(app)?).max_certs_behavior(MaxCertsBehavior::Prompt(Box::new(maxcb))).build())
}

#[derive(Debug,Clone,Serialize,Deserialize)]#[serde(rename_all="camelCase")]pub struct CertificateInfo{pub name:Option<String>,pub certificate_id:Option<String>,pub serial_number:Option<String>,pub machine_name:Option<String>,pub machine_id:Option<String>}
#[derive(Debug,Serialize)]#[serde(rename_all="camelCase")]pub struct SigningExportInfo{pub directory:String,pub p12_password:String,pub team_id:String,pub certificate_serial_number:String,pub machine_id:String,pub machine_name:String,pub profile_uuid:String,pub profile_name:String,pub app_identifier:String,pub profile_expiration_date:String,pub is_free_provisioning_profile:Option<bool>}
#[tauri::command]pub async fn get_certificates(s:State<'_,SideloaderMutex>)->Result<Vec<CertificateInfo>,AppError>{let mut l=SideloaderGuard::take(&s)?;let team=l.get_mut().get_team().await?;let c=l.get_mut().get_dev_session().list_all_development_certs(&team,None).await?;Ok(c.into_iter().map(|x|CertificateInfo{name:x.name,certificate_id:x.certificate_id,serial_number:x.serial_number,machine_name:x.machine_name,machine_id:x.machine_id}).collect())}
#[tauri::command]pub async fn revoke_certificate(serial_number:String,s:State<'_,SideloaderMutex>)->Result<(),AppError>{let mut l=SideloaderGuard::take(&s)?;let team=l.get_mut().get_team().await?;l.get_mut().get_dev_session().revoke_development_cert(&team,&serial_number,None).await?;Ok(())}
#[tauri::command]pub async fn list_app_ids(s:State<'_,SideloaderMutex>)->Result<ListAppIdsResponse,AppError>{let mut l=SideloaderGuard::take(&s)?;let team=l.get_mut().get_team().await?;Ok(l.get_mut().get_dev_session().list_app_ids(&team,None).await?)}
#[tauri::command]pub async fn delete_app_id(app_id_id:String,s:State<'_,SideloaderMutex>)->Result<(),AppError>{let mut l=SideloaderGuard::take(&s)?;let team=l.get_mut().get_team().await?;l.get_mut().get_dev_session().delete_app_id(&team,&app_id_id,None).await?;Ok(())}

#[tauri::command]
pub async fn export_signing_bundle(handle:AppHandle,s:State<'_,SideloaderMutex>,app_id_id:String,password:Option<String>)->Result<Option<SigningExportInfo>,AppError>{
 let dir=handle.dialog().file().set_title("Choose a folder for the signing bundle").blocking_pick_folder();let Some(dir)=dir else{return Ok(None)};let path=dir.into_path().map_err(|e|AppError::Filesystem("Invalid export directory".into(),e.to_string()))?;let mut l=SideloaderGuard::take(&s)?;let identity=l.get_mut().export_signing_identity(password.as_deref()).await?;let profile=l.get_mut().export_provisioning_profile(&app_id_id).await?;std::fs::create_dir_all(&path).map_err(|e|AppError::Filesystem("Failed to create export directory".into(),e.to_string()))?;std::fs::write(path.join("development.p12"),&identity.p12).map_err(|e|AppError::Filesystem("Failed to write P12".into(),e.to_string()))?;std::fs::write(path.join("development.mobileprovision"),&profile.mobileprovision).map_err(|e|AppError::Filesystem("Failed to write provisioning profile".into(),e.to_string()))?;
 let metadata=serde_json::json!({"teamId":identity.team_id,"certificateSerialNumber":identity.certificate_serial_number,"machineId":identity.machine_id,"machineName":identity.machine_name,"profileUuid":profile.uuid,"profileName":profile.name,"appIdentifier":profile.app_identifier,"profileExpirationDate":profile.expiration_date,"isFreeProvisioningProfile":profile.is_free_provisioning_profile});std::fs::write(path.join("certificate.json"),serde_json::to_vec_pretty(&metadata).map_err(|e|AppError::Misc(e.to_string()))?).map_err(|e|AppError::Filesystem("Failed to write metadata".into(),e.to_string()))?;
 Ok(Some(SigningExportInfo{directory:path.display().to_string(),p12_password:identity.p12_password,team_id:identity.team_id,certificate_serial_number:identity.certificate_serial_number,machine_id:identity.machine_id,machine_name:identity.machine_name,profile_uuid:profile.uuid,profile_name:profile.name,app_identifier:profile.app_identifier,profile_expiration_date:profile.expiration_date,is_free_provisioning_profile:profile.is_free_provisioning_profile}))
}
