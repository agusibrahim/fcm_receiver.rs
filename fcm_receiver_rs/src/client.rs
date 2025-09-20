use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::engine::general_purpose::{STANDARD as BASE64_STANDARD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use rand::Rng;
use reqwest::blocking::Client as HttpClient;

use crate::crypto::{create_keys, decode_private_key, encode_private_key, public_key_bytes};
use crate::encryption::decrypt_message;
use crate::error::{Error, Result};
use crate::http_client::{
    self, AndroidAppOptions, FcmInstallRequest, FcmRegisterRequest, GcmRegisterRequest,
};
use crate::messages::{
    create_check_in_request, create_login_request_raw, decode_data_message_stanza,
    ManualDataMessageStanza,
};
use crate::socket_handler::SocketHandler;
use crate::util;

use p256::{PublicKey, SecretKey};

pub struct AndroidApp {
    pub gcm_sender_id: String,
    pub android_package: String,
    pub android_package_cert: String,
}

pub struct FcmClient {
    pub vapid_key: String,
    pub api_key: String,
    pub app_id: String,
    pub project_id: String,
    pub gcm_token: Option<String>,
    pub fcm_token: Option<String>,
    pub android_id: u64,
    pub security_token: u64,
    pub heartbeat_interval: Duration,
    pub on_data_message: Option<Arc<dyn Fn(Vec<u8>) + Send + Sync>>,
    pub on_raw_message: Option<Arc<dyn Fn(ManualDataMessageStanza) + Send + Sync>>,
    pub android_app: Option<AndroidApp>,
    http_client: HttpClient,
    private_key: Option<SecretKey>,
    public_key: Option<PublicKey>,
    auth_secret: Option<Vec<u8>>,
    persistent_ids: Arc<Mutex<HashSet<String>>>,
    installation_auth_token: Option<String>,
    socket_handler: Option<SocketHandler>,
}

impl FcmClient {
    pub fn new(api_key: String, app_id: String, project_id: String) -> Result<Self> {
        let http_client = http_client::build_default_http_client()?;
        Ok(Self {
            vapid_key: String::new(),
            api_key,
            app_id,
            project_id,
            gcm_token: None,
            fcm_token: None,
            android_id: 0,
            security_token: 0,
            heartbeat_interval: Duration::from_secs(600),
            on_data_message: None,
            on_raw_message: None,
            android_app: None,
            http_client,
            private_key: None,
            public_key: None,
            auth_secret: None,
            persistent_ids: Arc::new(Mutex::new(HashSet::new())),
            installation_auth_token: None,
            socket_handler: None,
        })
    }

    pub fn with_http_client(
        api_key: String,
        app_id: String,
        project_id: String,
        http_client: HttpClient,
    ) -> Self {
        Self {
            vapid_key: String::new(),
            api_key,
            app_id,
            project_id,
            gcm_token: None,
            fcm_token: None,
            android_id: 0,
            security_token: 0,
            heartbeat_interval: Duration::from_secs(600),
            on_data_message: None,
            on_raw_message: None,
            android_app: None,
            http_client,
            private_key: None,
            public_key: None,
            auth_secret: None,
            persistent_ids: Arc::new(Mutex::new(HashSet::new())),
            installation_auth_token: None,
            socket_handler: None,
        }
    }

    pub fn create_new_keys(&mut self) -> Result<(String, String)> {
        let (private_key, public_key, auth_secret) = create_keys()?;
        let private_key_der = encode_private_key(&private_key)?;
        let private_key_b64 = BASE64_STANDARD.encode(private_key_der);
        let auth_secret_b64 = BASE64_STANDARD.encode(&auth_secret);

        self.private_key = Some(private_key);
        self.public_key = Some(public_key);
        self.auth_secret = Some(auth_secret);

        Ok((private_key_b64, auth_secret_b64))
    }

    pub fn load_keys(&mut self, private_key_b64: &str, auth_secret_b64: &str) -> Result<()> {
        let private_bytes = BASE64_STANDARD
            .decode(private_key_b64)
            .map_err(|_| Error::InvalidData("invalid private key encoding"))?;
        let private_key = decode_private_key(&private_bytes)?;
        let public_key = private_key.public_key();
        let auth_secret = BASE64_STANDARD
            .decode(auth_secret_b64)
            .map_err(|_| Error::InvalidData("invalid auth secret encoding"))?;

        self.private_key = Some(private_key);
        self.public_key = Some(public_key);
        self.auth_secret = Some(auth_secret);

        Ok(())
    }

    pub fn register(&mut self) -> Result<(String, String, u64, u64)> {
        if self.api_key.is_empty() || self.app_id.is_empty() || self.project_id.is_empty() {
            return Err(Error::InvalidData("missing ApiKey/AppId/ProjectId"));
        }

        if self.android_id == 0 || self.security_token == 0 {
            self.check_in_request_gcm()?;
        }

        if self.private_key.is_none() || self.auth_secret.is_none() {
            return Err(Error::InvalidData("keys not loaded"));
        }

        if self.gcm_token.is_none() && self.android_app.is_none() {
            let token = self.register_request_gcm()?;
            self.gcm_token = Some(token);
        } else if self.gcm_token.is_none() {
            let token = self.register_request_gcm()?;
            self.fcm_token = Some(token);
        }

        let install_token = self.install_request()?;
        self.installation_auth_token = Some(install_token);

        if self.android_app.is_none() {
            let token = self.register_request()?;
            self.fcm_token = Some(token);
        }

        let fcm_token = self
            .fcm_token
            .clone()
            .ok_or_else(|| Error::InvalidData("FCM token not available"))?;
        let gcm_token = self.gcm_token.clone().unwrap_or_default();

        Ok((fcm_token, gcm_token, self.android_id, self.security_token))
    }

    fn check_in_request_gcm(&mut self) -> Result<()> {
        let request = create_check_in_request(self.android_id as i64, Some(self.security_token));
        let response = http_client::send_gcm_check_in_request(&self.http_client, &request)?;
        if let Some(android_id) = response.android_id {
            self.android_id = android_id;
        }
        if let Some(security_token) = response.security_token {
            self.security_token = security_token;
        }
        Ok(())
    }

    fn register_request_gcm(&mut self) -> Result<String> {
        let android_app = self.android_app.as_ref().map(|app| AndroidAppOptions {
            gcm_sender_id: app.gcm_sender_id.as_str(),
            android_package: app.android_package.as_str(),
            android_package_cert: app.android_package_cert.as_str(),
        });

        let request = GcmRegisterRequest {
            android_id: self.android_id,
            security_token: self.security_token,
            app_id: self.app_id.as_str(),
            android_app,
            installation_auth: self.installation_auth_token.as_deref(),
            sender_override: None,
            subtype_override: None,
            delete: false,
            extra_params: Vec::new(),
        };

        let token = http_client::send_gcm_register_request(&self.http_client, &request)?;
        if self.android_app.is_none() {
            self.gcm_token = Some(token.clone());
        } else {
            self.fcm_token = Some(token.clone());
        }
        Ok(token)
    }

    fn install_request(&mut self) -> Result<String> {
        let fid = util::generate_firebase_fid()?;
        let android_app = self.android_app.as_ref().map(|app| AndroidAppOptions {
            gcm_sender_id: app.gcm_sender_id.as_str(),
            android_package: app.android_package.as_str(),
            android_package_cert: app.android_package_cert.as_str(),
        });
        let request = FcmInstallRequest {
            api_key: self.api_key.as_str(),
            project_id: self.project_id.as_str(),
            app_id: self.app_id.as_str(),
            fid: fid.as_str(),
            android_app,
            firebase_client_header: None,
            firebase_client_log_type: None,
            user_agent: None,
        };
        let response = http_client::send_fcm_install_request(&self.http_client, &request)?;
        Ok(response.auth_token.token)
    }

    fn register_request(&mut self) -> Result<String> {
        let public_key = self
            .public_key
            .as_ref()
            .ok_or_else(|| Error::InvalidData("public key missing"))?;
        let auth_secret = self
            .auth_secret
            .as_ref()
            .ok_or_else(|| Error::InvalidData("auth secret missing"))?;
        let installation_auth = self
            .installation_auth_token
            .as_ref()
            .ok_or_else(|| Error::InvalidData("installation auth missing"))?;
        let gcm_token = self
            .gcm_token
            .as_ref()
            .ok_or_else(|| Error::InvalidData("GCM token missing"))?;

        let mut public_key_b64 = URL_SAFE_NO_PAD.encode(public_key_bytes(public_key));
        public_key_b64 = public_key_b64.replace('=', "");

        let mut auth_secret_b64 = URL_SAFE_NO_PAD.encode(auth_secret);
        auth_secret_b64 = auth_secret_b64.replace('=', "");

        let endpoint = http_client::build_endpoint_url(gcm_token);

        let request = FcmRegisterRequest {
            api_key: self.api_key.as_str(),
            project_id: self.project_id.as_str(),
            installation_auth: installation_auth.as_str(),
            vapid_key: self.vapid_key.as_str(),
            auth_secret: auth_secret_b64.as_str(),
            endpoint: endpoint.as_str(),
            p256dh: public_key_b64.as_str(),
        };

        let response = http_client::send_fcm_register_request(&self.http_client, &request)?;
        Ok(response.token)
    }

    pub fn start_listening(&mut self) -> Result<()> {
        if self.android_id == 0 || self.security_token == 0 {
            return Err(Error::InvalidData("client's AndroidId and SecurityToken hasn't been set. use FcmClient.register() to generate a new AndroidId and SecurityToken"));
        }

        if self.private_key.is_none() || self.auth_secret.is_none() {
            return Err(Error::InvalidData("client's private key hasn't been set. use FcmClient.load_keys() or FcmClient.create_new_keys()"));
        }

        let persistent_ids: Vec<String> = self
            .persistent_ids
            .lock()
            .unwrap()
            .iter()
            .cloned()
            .collect();
        let login_request =
            create_login_request_raw(self.android_id, self.security_token, &persistent_ids)?;

        let mut socket_handler = SocketHandler::new();
        socket_handler.set_heartbeat_interval(self.heartbeat_interval);

        let on_data_message = self.on_data_message.clone();
        let on_raw_message = self.on_raw_message.clone();
        let persistent_ids_clone = self.persistent_ids.clone();
        let auth_secret = self.auth_secret.clone();
        let private_key = self.private_key.clone();

        socket_handler.set_on_message(move |tag, data| {
            Self::handle_message(
                tag,
                data,
                &on_data_message,
                &on_raw_message,
                &persistent_ids_clone,
                &auth_secret,
                &private_key,
            )
        });

        socket_handler.connect()?;
        socket_handler.send_login_handshake(&login_request)?;

        self.socket_handler = Some(socket_handler);

        if let Some(handler) = self.socket_handler.as_mut() {
            handler.start_socket_handler()
        } else {
            Err(Error::Other(
                "Socket handler initialization failed".to_string(),
            ))
        }
    }

    fn handle_message(
        tag: u8,
        data: Vec<u8>,
        on_data_message: &Option<Arc<dyn Fn(Vec<u8>) + Send + Sync>>,
        on_raw_message: &Option<Arc<dyn Fn(ManualDataMessageStanza) + Send + Sync>>,
        persistent_ids: &Arc<Mutex<HashSet<String>>>,
        auth_secret: &Option<Vec<u8>>,
        private_key: &Option<SecretKey>,
    ) -> Result<()> {
        use crate::consts::*;

        match tag {
            K_HEARTBEAT_PING_TAG | K_HEARTBEAT_ACK_TAG | K_LOGIN_RESPONSE_TAG => Ok(()),
            K_CLOSE_TAG => Err(Error::Other("server returned close tag".to_string())),
            K_IQ_STANZA_TAG => Ok(()),
            K_DATA_MESSAGE_STANZA_TAG => {
                let message = decode_data_message_stanza(&data)?;

                if let Some(ref persistent_id) = message.persistent_id {
                    let ttl_duration = message
                        .ttl
                        .and_then(|ttl| {
                            if ttl > 0 {
                                Some(Duration::from_secs(ttl as u64))
                            } else {
                                None
                            }
                        })
                        .unwrap_or_else(|| Duration::from_secs(DEFAULT_FCM_MESSAGE_TTL_SECS));

                    let mut ids = persistent_ids.lock().unwrap();
                    if ids.contains(persistent_id) {
                        return Ok(());
                    }
                    ids.insert(persistent_id.clone());
                    drop(ids);

                    let persistent_id_clone = persistent_id.clone();
                    let persistent_ids_clone = Arc::clone(persistent_ids);
                    std::thread::spawn(move || {
                        std::thread::sleep(ttl_duration);
                        if let Ok(mut guard) = persistent_ids_clone.lock() {
                            guard.remove(&persistent_id_clone);
                        }
                    });
                }

                let mut crypto_key_bytes: Option<Vec<u8>> = None;
                let mut encryption_bytes: Option<Vec<u8>> = None;
                let mut is_raw = true;

                for app_data in &message.app_data {
                    if app_data.key == "crypto-key" {
                        is_raw = false;
                        if let Some(dh_part) = app_data
                            .value
                            .split(';')
                            .find(|part| part.starts_with("dh="))
                        {
                            let encoded = dh_part
                                .get(3..)
                                .ok_or_else(|| Error::InvalidData("invalid dh parameter"))?;
                            crypto_key_bytes = Some(Self::decode_base64_url(encoded)?);
                        }
                    } else if app_data.key == "encryption" {
                        if let Some(salt_part) = app_data
                            .value
                            .split(';')
                            .find(|part| part.starts_with("salt="))
                        {
                            let encoded = salt_part
                                .get(5..)
                                .ok_or_else(|| Error::InvalidData("invalid salt parameter"))?;
                            encryption_bytes = Some(Self::decode_base64_url(encoded)?);
                        }
                    }
                }

                if !is_raw {
                    if let (
                        Some(crypto_key),
                        Some(encryption),
                        Some(auth_secret),
                        Some(private_key),
                    ) = (
                        crypto_key_bytes.as_ref(),
                        encryption_bytes.as_ref(),
                        auth_secret.as_ref(),
                        private_key.as_ref(),
                    ) {
                        let decrypted = decrypt_message(
                            crypto_key,
                            encryption,
                            message
                                .raw_data
                                .as_deref()
                                .ok_or_else(|| Error::InvalidData("missing raw data payload"))?,
                            auth_secret,
                            private_key,
                        )?;

                        if let Some(callback) = on_data_message {
                            callback(decrypted);
                        }
                    }
                } else if let Some(callback) = on_raw_message {
                    callback(message);
                }

                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn decode_base64_url(value: &str) -> Result<Vec<u8>> {
        let mut input = value.to_string();
        while input.len() % 4 != 0 {
            input.push('=');
        }

        URL_SAFE
            .decode(input.as_bytes())
            .map_err(|_| Error::InvalidData("invalid base64 value"))
    }

    pub fn close(&mut self) {
        if let Some(mut socket_handler) = self.socket_handler.take() {
            socket_handler.close();
        }
    }

    pub fn remove_persistent_id(&self, id: &str) {
        self.persistent_ids.lock().unwrap().remove(id);
    }

    pub fn subscribe_to_topic(&self, topic: &str) -> Result<()> {
        let normalized = topic.strip_prefix("/topics/").unwrap_or(topic);
        http_client::validate_topic_name(normalized)?;

        if self.android_id == 0 || self.security_token == 0 {
            return Err(Error::InvalidData(
                "client's AndroidId and SecurityToken hasn't been set. use FcmClient.register() first",
            ));
        }

        let fcm_token = self
            .fcm_token
            .as_ref()
            .ok_or_else(|| Error::InvalidData("FCM token not available"))?;

        let topic_path = format!("/topics/{normalized}");

        let android_app = self.android_app.as_ref().map(|app| AndroidAppOptions {
            gcm_sender_id: app.gcm_sender_id.as_str(),
            android_package: app.android_package.as_str(),
            android_package_cert: app.android_package_cert.as_str(),
        });

        let extra_params = vec![
            ("X-gcm.topic".to_string(), topic_path.clone()),
            ("X-scope".to_string(), topic_path.clone()),
            ("X-subscription".to_string(), fcm_token.clone()),
            ("X-kid".to_string(), Self::generate_kid()),
        ];

        let request = GcmRegisterRequest {
            android_id: self.android_id,
            security_token: self.security_token,
            app_id: self.app_id.as_str(),
            android_app,
            installation_auth: self.installation_auth_token.as_deref(),
            sender_override: Some(fcm_token.clone()),
            subtype_override: Some(fcm_token.clone()),
            delete: false,
            extra_params,
        };

        http_client::send_gcm_register_request(&self.http_client, &request)?;
        Ok(())
    }

    pub fn unsubscribe_from_topic(&self, topic: &str) -> Result<()> {
        let normalized = topic.strip_prefix("/topics/").unwrap_or(topic);
        http_client::validate_topic_name(normalized)?;

        if self.android_id == 0 || self.security_token == 0 {
            return Err(Error::InvalidData(
                "client's AndroidId and SecurityToken hasn't been set. use FcmClient.register() first",
            ));
        }

        let fcm_token = self
            .fcm_token
            .as_ref()
            .ok_or_else(|| Error::InvalidData("FCM token not available"))?;

        let topic_path = format!("/topics/{normalized}");

        let android_app = self.android_app.as_ref().map(|app| AndroidAppOptions {
            gcm_sender_id: app.gcm_sender_id.as_str(),
            android_package: app.android_package.as_str(),
            android_package_cert: app.android_package_cert.as_str(),
        });

        let extra_params = vec![
            ("X-gcm.topic".to_string(), topic_path.clone()),
            ("X-scope".to_string(), topic_path.clone()),
            ("X-subscription".to_string(), fcm_token.clone()),
            ("X-kid".to_string(), Self::generate_kid()),
            ("X-delete".to_string(), "1".to_string()),
        ];

        let request = GcmRegisterRequest {
            android_id: self.android_id,
            security_token: self.security_token,
            app_id: self.app_id.as_str(),
            android_app,
            installation_auth: self.installation_auth_token.as_deref(),
            sender_override: Some(fcm_token.clone()),
            subtype_override: Some(fcm_token.clone()),
            delete: true,
            extra_params,
        };

        http_client::send_gcm_register_request(&self.http_client, &request)?;
        Ok(())
    }

    fn generate_kid() -> String {
        let mut rng = rand::thread_rng();
        let value: u32 = rng.gen_range(1..1_000_000);
        format!("|ID|{}|", value)
    }
}
