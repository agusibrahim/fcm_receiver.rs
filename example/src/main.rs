use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use fcm_receiver_rs::Result;
use fcm_receiver_rs::client::FcmClient;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct DeviceCredentials {
    #[serde(default)]
    api_key: String,
    #[serde(default)]
    app_id: String,
    #[serde(default)]
    project_id: String,
    fcm_token: String,
    gcm_token: String,
    android_id: u64,
    security_token: u64,
    private_key_base64: String,
    auth_secret_base64: String,
}

fn load_credentials(path: &PathBuf) -> Result<DeviceCredentials> {
    let bytes = fs::read(path)?;
    let creds: DeviceCredentials = serde_json::from_slice(&bytes)?;
    if creds.android_id == 0
        || creds.security_token == 0
        || creds.private_key_base64.is_empty()
        || creds.auth_secret_base64.is_empty()
    {
        return Err(fcm_receiver_rs::Error::InvalidData(
            "incomplete credentials in json",
        ));
    }
    Ok(creds)
}

fn save_credentials(path: &PathBuf, creds: &DeviceCredentials) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(creds)?;
    fs::write(path, json)?;
    Ok(())
}

fn main() -> Result<()> {
    const API_KEY: &str = "AIzaSyabHiDUp....joKOwI-feQYwg";
    const APP_ID: &str = "1:xxxx:android:xxxx";
    const PROJECT_ID: &str = "xxxx-yyyy";
    const TOPIC_TO_SUBSCRIBE: &str = "promotions";

    let credentials_path = PathBuf::from("device_credentials.json");

    let mut client = FcmClient::new(
        API_KEY.to_string(),
        APP_ID.to_string(),
        PROJECT_ID.to_string(),
    )?;
    client.on_data_message = Some(Arc::new(|payload| {
        let text = String::from_utf8_lossy(&payload);
        println!("Received message: {}", &text);
    }));
    client.on_raw_message = Some(Arc::new(|msg| {
        println!("Received raw stanza: {msg:?}");
    }));

    if credentials_path.exists() {
        let creds = load_credentials(&credentials_path)?;
        client.gcm_token = Some(creds.gcm_token.clone());
        client.fcm_token = Some(creds.fcm_token.clone());
        client.android_id = creds.android_id;
        client.security_token = creds.security_token;
        client.load_keys(&creds.private_key_base64, &creds.auth_secret_base64)?;
        println!("Loaded device credentials: {:#?}", creds);
    } else {
        let (private_key_b64, auth_secret_b64) = client.create_new_keys()?;
        client.load_keys(&private_key_b64, &auth_secret_b64)?;
        let (fcm_token, gcm_token, android_id, security_token) = client.register()?;

        let creds = DeviceCredentials {
            api_key: API_KEY.to_string(),
            app_id: APP_ID.to_string(),
            project_id: PROJECT_ID.to_string(),
            fcm_token: fcm_token.clone(),
            gcm_token: gcm_token.clone(),
            android_id,
            security_token,
            private_key_base64: private_key_b64,
            auth_secret_base64: auth_secret_b64,
        };
        save_credentials(&credentials_path, &creds)?;
        println!("Registered new device: {:#?}", creds);
    }
    if let Err(err) = client.subscribe_to_topic(TOPIC_TO_SUBSCRIBE) {
        println!("error sub topic: {err}");
    } else {
        println!("topic subscribed '{TOPIC_TO_SUBSCRIBE}'");
    }

    if let Err(err) = client.start_listening() {
        eprintln!("start_listening not available yet: {err}");
    }

    Ok(())
}
