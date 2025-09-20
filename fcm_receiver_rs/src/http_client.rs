use std::collections::HashMap;

use base64::engine::general_purpose::{STANDARD as BASE64_STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE, USER_AGENT};
use serde::{Deserialize, Serialize};
use url::form_urlencoded;

use crate::consts::{
    CHECK_IN_URL, FCM_ENDPOINT_URL, FIREBASE_INSTALLATION_URL, FIREBASE_REGISTRATION_URL,
    REGISTER_URL,
};
use crate::error::{Error, Result};
use crate::messages::{
    marshal_android_checkin_request, unmarshal_android_checkin_response,
    ManualAndroidCheckinRequest, ManualAndroidCheckinResponse,
};

#[derive(Debug, Clone, Deserialize)]
pub struct AuthToken {
    #[serde(rename = "token")]
    pub token: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FcmInstallationResponse {
    #[serde(rename = "authToken")]
    pub auth_token: AuthToken,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FcmRegisterResponse {
    #[serde(rename = "token")]
    pub token: String,
    #[serde(rename = "pushSet")]
    pub push_set: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AndroidAppOptions<'a> {
    pub gcm_sender_id: &'a str,
    pub android_package: &'a str,
    pub android_package_cert: &'a str,
}

#[derive(Debug, Clone)]
pub struct GcmRegisterRequest<'a> {
    pub android_id: u64,
    pub security_token: u64,
    pub app_id: &'a str,
    pub android_app: Option<AndroidAppOptions<'a>>,
    pub installation_auth: Option<&'a str>,
    pub sender_override: Option<String>,
    pub subtype_override: Option<String>,
    pub delete: bool,
    pub extra_params: Vec<(String, String)>,
}

#[derive(Debug, Clone)]
pub struct FcmInstallRequest<'a> {
    pub api_key: &'a str,
    pub project_id: &'a str,
    pub app_id: &'a str,
    pub fid: &'a str,
    pub android_app: Option<AndroidAppOptions<'a>>,
    pub firebase_client_header: Option<&'a str>,
    pub firebase_client_log_type: Option<&'a str>,
    pub user_agent: Option<&'a str>,
}

#[derive(Debug, Clone)]
pub struct FcmRegisterRequest<'a> {
    pub api_key: &'a str,
    pub project_id: &'a str,
    pub installation_auth: &'a str,
    pub vapid_key: &'a str,
    pub auth_secret: &'a str,
    pub endpoint: &'a str,
    pub p256dh: &'a str,
}

pub fn build_default_http_client() -> Result<Client> {
    let client = Client::builder().build()?;
    Ok(client)
}

pub fn validate_topic_name(topic: &str) -> Result<()> {
    if topic.is_empty() {
        return Err(Error::InvalidData("topic name is empty"));
    }

    if !topic
        .chars()
        .all(|c| matches!(c, 'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' | '~' | '%'))
    {
        return Err(Error::InvalidData(
            "topic name contains invalid characters. allowed: a-z, A-Z, 0-9, '-', '_', '.', '~', '%'",
        ));
    }

    Ok(())
}

pub fn send_gcm_check_in_request(
    client: &Client,
    request_body: &ManualAndroidCheckinRequest,
) -> Result<ManualAndroidCheckinResponse> {
    let body = marshal_android_checkin_request(request_body)?;

    let mut headers = HeaderMap::new();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/x-protobuf"),
    );
    headers.insert(USER_AGENT, HeaderValue::from_static(""));

    let response = client
        .post(CHECK_IN_URL)
        .headers(headers)
        .body(body)
        .send()?;

    let status = response.status();
    let bytes = response.bytes()?;
    if !status.is_success() {
        return Err(Error::Other(format!(
            "check-in HTTP {}: {}",
            status,
            String::from_utf8_lossy(&bytes)
        )));
    }

    let message = unmarshal_android_checkin_response(&bytes)?;
    Ok(message)
}

pub fn send_gcm_register_request(client: &Client, cfg: &GcmRegisterRequest<'_>) -> Result<String> {
    let mut params: HashMap<String, String> = HashMap::new();

    match &cfg.android_app {
        Some(app) => {
            let subtype_value = cfg.subtype_override.as_deref().unwrap_or(app.gcm_sender_id);
            params.insert("X-subtype".to_string(), subtype_value.to_string());
            params.insert("device".to_string(), cfg.android_id.to_string());
            params.insert("app".to_string(), app.android_package.to_string());
            params.insert("cert".to_string(), app.android_package_cert.to_string());
            params.insert("app_ver".to_string(), "1".to_string());
            params.insert("X-app_ver".to_string(), "1".to_string());
            params.insert("X-osv".to_string(), "29".to_string());
            params.insert("X-cliv".to_string(), "fiid-21.1.1".to_string());
            params.insert("X-gmsv".to_string(), "220217001".to_string());
            params.insert("X-scope".to_string(), "*".to_string());
            if let Some(auth) = cfg.installation_auth {
                params.insert(
                    "X-Goog-Firebase-Installations-Auth".to_string(),
                    auth.to_string(),
                );
            }
            params.insert("X-gms_app_id".to_string(), cfg.app_id.to_string());
            params.insert(
                "X-Firebase-Client".to_string(),
                "android-min-sdk/23 fire-core/20.0.0 device-name/a21snnxx device-brand/samsung device-model/a21s android-installer/com.android.vending fire-android/30 fire-installations/17.0.0 fire-fcm/22.0.0 android-platform/ kotlin/1.9.23 android-target-sdk/34".to_string(),
            );
            params.insert("X-Firebase-Client-Log-Type".to_string(), "1".to_string());
            params.insert("X-app_ver_name".to_string(), "1".to_string());
            params.insert("target_ver".to_string(), "31".to_string());
            let sender_value = cfg
                .sender_override
                .as_ref()
                .map(|s| s.as_str())
                .unwrap_or(app.gcm_sender_id);
            params.insert("sender".to_string(), sender_value.to_string());
        }
        None => {
            let subtype_value = cfg.subtype_override.as_deref().unwrap_or(cfg.app_id);
            params.insert("X-subtype".to_string(), subtype_value.to_string());
            params.insert("app".to_string(), "org.chromium.linux".to_string());
            params.insert("device".to_string(), cfg.android_id.to_string());
            let default_sender = URL_SAFE_NO_PAD.encode(crate::consts::FCM_SERVER_KEY);
            let sender_value = cfg
                .sender_override
                .as_ref()
                .map(|s| s.as_str())
                .unwrap_or(default_sender.as_str());
            params.insert("sender".to_string(), sender_value.to_string());
            params.insert("X-gms_app_id".to_string(), cfg.app_id.to_string());
        }
    }

    if cfg.delete {
        params.insert("delete".to_string(), "1".to_string());
        params.insert("X-delete".to_string(), "1".to_string());
    }

    for (key, value) in &cfg.extra_params {
        params.insert(key.clone(), value.clone());
    }

    let mut serializer = form_urlencoded::Serializer::new(String::new());
    for (k, v) in &params {
        serializer.append_pair(k, v);
    }
    let body = serializer.finish();

    let authorization_value = format!("AidLogin {}:{}", cfg.android_id, cfg.security_token);

    let response = client
        .post(REGISTER_URL)
        .header("Authorization", authorization_value)
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(USER_AGENT, "")
        .body(body)
        .send()?;

    let status = response.status();
    let body_bytes = response.bytes()?;
    if !status.is_success() {
        return Err(Error::Other(format!(
            "register HTTP {}: {}",
            status,
            String::from_utf8_lossy(&body_bytes)
        )));
    }

    let body_str = String::from_utf8_lossy(&body_bytes);
    let parsed: HashMap<String, String> = form_urlencoded::parse(body_str.as_bytes())
        .into_owned()
        .collect();

    if let Some(err) = parsed.get("Error") {
        return Err(Error::Other(err.clone()));
    }

    parsed
        .get("token")
        .cloned()
        .ok_or_else(|| Error::InvalidData("missing token in register response"))
}

pub fn send_fcm_install_request(
    client: &Client,
    cfg: &FcmInstallRequest<'_>,
) -> Result<FcmInstallationResponse> {
    #[derive(Serialize)]
    struct Body<'a> {
        fid: &'a str,
        #[serde(rename = "appId")]
        app_id: &'a str,
        #[serde(rename = "authVersion")]
        auth_version: &'a str,
        #[serde(rename = "sdkVersion")]
        sdk_version: &'a str,
    }

    let mut headers = HeaderMap::new();
    headers.insert("Accept", HeaderValue::from_static("application/json"));
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    let api_key_header = HeaderValue::from_str(cfg.api_key)
        .map_err(|err| Error::Other(format!("invalid api key header: {err}")))?;
    headers.insert("x-goog-api-key", api_key_header);

    let sdk_version = if cfg.android_app.is_some() {
        "a:17.0.0"
    } else {
        "w:0.6.4"
    };

    let body = Body {
        fid: cfg.fid,
        app_id: cfg.app_id,
        auth_version: "FIS_v2",
        sdk_version,
    };

    let mut request = client
        .post(format!(
            "{}projects/{}/installations",
            FIREBASE_INSTALLATION_URL, cfg.project_id
        ))
        .headers(headers)
        .json(&body);

    if let Some(app) = &cfg.android_app {
        request = request
            .header("X-Android-Package", app.android_package)
            .header("X-Android-Cert", app.android_package_cert)
            .header(
                "x-firebase-client",
                cfg.firebase_client_header.unwrap_or("android-min-sdk/23 fire-core/20.0.0 device-name/a21snnxx device-brand/samsung device-model/a21s android-installer/com.android.vending fire-android/30 fire-installations/17.0.0 fire-fcm/22.0.0 android-platform/ kotlin/1.9.23 android-target-sdk/34"),
            )
            .header(
                "x-firebase-client-log-type",
                cfg.firebase_client_log_type.unwrap_or("3"),
            )
            .header(
                USER_AGENT,
                cfg.user_agent.unwrap_or("Dalvik/2.1.0 (Linux; U; Android 11; SM-A217F Build/RP1A.200720.012)"),
            );
    } else {
        let client_info = serde_json::json!({
            "heartbeats": [],
            "version": 2,
        });
        let encoded = BASE64_STANDARD.encode(client_info.to_string());
        request = request.header("x-firebase-client", encoded);
    }

    let response = request.send()?;
    let status = response.status();
    let bytes = response.bytes()?;
    if !status.is_success() {
        return Err(Error::Other(format!(
            "installation HTTP {}: {}",
            status,
            String::from_utf8_lossy(&bytes)
        )));
    }

    let parsed: FcmInstallationResponse = serde_json::from_slice(&bytes)?;
    Ok(parsed)
}

pub fn send_fcm_register_request(
    client: &Client,
    cfg: &FcmRegisterRequest<'_>,
) -> Result<FcmRegisterResponse> {
    #[derive(Serialize)]
    struct Web<'a> {
        #[serde(rename = "applicationPubKey")]
        application_pub_key: &'a str,
        auth: &'a str,
        endpoint: &'a str,
        #[serde(rename = "p256dh")]
        p256dh: &'a str,
    }

    #[derive(Serialize)]
    struct Body<'a> {
        web: Web<'a>,
    }

    let body = Body {
        web: Web {
            application_pub_key: cfg.vapid_key,
            auth: cfg.auth_secret,
            endpoint: cfg.endpoint,
            p256dh: cfg.p256dh,
        },
    };

    let response = client
        .post(format!(
            "{}projects/{}/registrations",
            FIREBASE_REGISTRATION_URL, cfg.project_id
        ))
        .header("x-goog-api-key", cfg.api_key)
        .header("x-goog-firebase-installations-auth", cfg.installation_auth)
        .header(CONTENT_TYPE, "application/json")
        .json(&body)
        .send()?;

    let status = response.status();
    let bytes = response.bytes()?;
    if !status.is_success() {
        return Err(Error::Other(format!(
            "register HTTP {}: {}",
            status,
            String::from_utf8_lossy(&bytes)
        )));
    }

    let parsed: FcmRegisterResponse = serde_json::from_slice(&bytes)?;
    Ok(parsed)
}

pub fn build_endpoint_url(token: &str) -> String {
    format!("{}/{}", FCM_ENDPOINT_URL.trim_end_matches('/'), token)
}
