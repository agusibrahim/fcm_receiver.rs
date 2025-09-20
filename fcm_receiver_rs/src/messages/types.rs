use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManualDeviceType {
    AndroidOs = 1,
    IosOs = 2,
    ChromeBrowser = 3,
    ChromeOs = 4,
}

impl Default for ManualDeviceType {
    fn default() -> Self {
        ManualDeviceType::AndroidOs
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManualChromeBuildPlatform {
    Win = 1,
    Mac = 2,
    Linux = 3,
    Cros = 4,
    Ios = 5,
    Android = 6,
}

impl Default for ManualChromeBuildPlatform {
    fn default() -> Self {
        ManualChromeBuildPlatform::Linux
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManualChromeBuildChannel {
    Stable = 1,
    Beta = 2,
    Dev = 3,
    Canary = 4,
    Unknown = 5,
}

impl Default for ManualChromeBuildChannel {
    fn default() -> Self {
        ManualChromeBuildChannel::Stable
    }
}

#[derive(Debug, Clone, Default)]
pub struct ManualChromeBuildProto {
    pub platform: Option<ManualChromeBuildPlatform>,
    pub chrome_version: Option<String>,
    pub channel: Option<ManualChromeBuildChannel>,
}

#[derive(Debug, Clone, Default)]
pub struct ManualAndroidCheckinProto {
    pub last_checkin_msec: Option<i64>,
    pub cell_operator: Option<String>,
    pub sim_operator: Option<String>,
    pub roaming: Option<String>,
    pub user_number: Option<i32>,
    pub device_type: Option<ManualDeviceType>,
    pub chrome_build: Option<ManualChromeBuildProto>,
}

#[derive(Debug, Clone, Default)]
pub struct ManualGservicesSetting {
    pub name: Vec<u8>,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone, Default)]
pub struct ManualAndroidCheckinRequest {
    pub imei: Option<String>,
    pub meid: Option<String>,
    pub mac_addr: Vec<String>,
    pub mac_addr_type: Vec<String>,
    pub serial_number: Option<String>,
    pub esn: Option<String>,
    pub id: Option<i64>,
    pub logging_id: Option<i64>,
    pub digest: Option<String>,
    pub locale: Option<String>,
    pub checkin: Option<ManualAndroidCheckinProto>,
    pub desired_build: Option<String>,
    pub market_checkin: Option<String>,
    pub account_cookie: Vec<String>,
    pub time_zone: Option<String>,
    pub security_token: Option<u64>,
    pub version: Option<i32>,
    pub ota_cert: Vec<String>,
    pub fragment: Option<i32>,
    pub user_name: Option<String>,
    pub user_serial_number: Option<i32>,
}

#[derive(Debug, Clone, Default)]
pub struct ManualAndroidCheckinResponse {
    pub stats_ok: Option<bool>,
    pub time_msec: Option<i64>,
    pub digest: Option<String>,
    pub settings_diff: Option<bool>,
    pub delete_setting: Vec<String>,
    pub setting: Vec<ManualGservicesSetting>,
    pub market_ok: Option<bool>,
    pub android_id: Option<u64>,
    pub security_token: Option<u64>,
    pub version_info: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct ManualHeartbeatPing {
    pub stream_id: Option<i32>,
    pub last_stream_id_received: Option<i32>,
    pub status: Option<i64>,
}

#[derive(Debug, Clone, Default)]
pub struct ManualHeartbeatAck {
    pub stream_id: Option<i32>,
    pub last_stream_id_received: Option<i32>,
    pub status: Option<i64>,
}

#[derive(Debug, Clone, Default)]
pub struct ManualErrorInfo {
    pub code: Option<i32>,
    pub message: Option<String>,
    pub error_type: Option<String>,
    pub extension: Option<ManualExtension>,
}

#[derive(Debug, Clone, Default)]
pub struct ManualSetting {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Default)]
pub struct ManualHeartbeatStat {
    pub ip: Option<String>,
    pub timeout: Option<bool>,
    pub interval_ms: Option<i32>,
}

#[derive(Debug, Clone, Default)]
pub struct ManualHeartbeatConfig {
    pub upload_stat: Option<bool>,
    pub ip: Option<String>,
    pub interval_ms: Option<i32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManualClientEventType {
    Unknown = 0,
    UnvisitMcs = 1,
}

impl Default for ManualClientEventType {
    fn default() -> Self {
        ManualClientEventType::Unknown
    }
}

#[derive(Debug, Clone, Default)]
pub struct ManualClientEvent {
    pub event_type: Option<ManualClientEventType>,
    pub number_discarded_events: Option<u32>,
    pub network_type: Option<i32>,
    pub time_connection_started_ms: Option<u64>,
    pub time_connection_ended_ms: Option<u64>,
    pub error_code: Option<i32>,
    pub time_connection_established_ms: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManualLoginRequestAuthService {
    AndroidId = 2,
}

impl Default for ManualLoginRequestAuthService {
    fn default() -> Self {
        ManualLoginRequestAuthService::AndroidId
    }
}

#[derive(Debug, Clone, Default)]
pub struct ManualLoginRequest {
    pub id: String,
    pub domain: String,
    pub user: String,
    pub resource: String,
    pub auth_token: String,
    pub device_id: String,
    pub last_rmq_id: Option<i64>,
    pub setting: Vec<ManualSetting>,
    pub received_persistent_id: Vec<String>,
    pub adaptive_heartbeat: Option<bool>,
    pub heartbeat_stat: Option<ManualHeartbeatStat>,
    pub use_rmq2: Option<bool>,
    pub account_id: Option<i64>,
    pub auth_service: Option<ManualLoginRequestAuthService>,
    pub network_type: Option<i32>,
    pub status: Option<i64>,
    pub client_event: Vec<ManualClientEvent>,
}

#[derive(Debug, Clone, Default)]
pub struct ManualLoginResponse {
    pub id: Option<String>,
    pub jid: Option<String>,
    pub error: Option<ManualErrorInfo>,
    pub setting: Vec<ManualSetting>,
    pub stream_id: Option<i32>,
    pub last_stream_id_received: Option<i32>,
    pub heartbeat_config: Option<ManualHeartbeatConfig>,
    pub server_timestamp: Option<i64>,
}

#[derive(Debug, Clone, Default)]
pub struct ManualClose;

#[derive(Debug, Clone, Default)]
pub struct ManualStreamErrorStanza {
    pub error_type: Option<String>,
    pub text: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct ManualExtension {
    pub id: Option<i32>,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManualIqStanzaType {
    Get = 0,
    Set = 1,
    Result = 2,
    Error = 3,
}

impl Default for ManualIqStanzaType {
    fn default() -> Self {
        ManualIqStanzaType::Get
    }
}

#[derive(Debug, Clone, Default)]
pub struct ManualIqStanza {
    pub rmq_id: Option<i64>,
    pub stanza_type: Option<ManualIqStanzaType>,
    pub id: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub error: Option<ManualErrorInfo>,
    pub extension: Option<ManualExtension>,
    pub persistent_id: Option<String>,
    pub stream_id: Option<i32>,
    pub last_stream_id_received: Option<i32>,
    pub account_id: Option<i64>,
    pub status: Option<i64>,
}

#[derive(Debug, Clone, Default)]
pub struct ManualAppData {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone, Default)]
pub struct ManualDataMessageStanza {
    pub id: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub category: Option<String>,
    pub token: Option<String>,
    pub app_data: Vec<ManualAppData>,
    pub from_trusted_server: Option<bool>,
    pub persistent_id: Option<String>,
    pub stream_id: Option<i32>,
    pub last_stream_id_received: Option<i32>,
    pub reg_id: Option<String>,
    pub device_user_id: Option<i64>,
    pub ttl: Option<i32>,
    pub sent: Option<i64>,
    pub queued: Option<i32>,
    pub status: Option<i64>,
    pub raw_data: Option<Vec<u8>>,
    pub immediate_ack: Option<bool>,
}

#[derive(Debug, Clone, Default)]
pub struct ManualStreamAck;

#[derive(Debug, Clone, Default)]
pub struct ManualSelectiveAck {
    pub id: Vec<String>,
}

impl fmt::Display for ManualDataMessageStanza {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ManualDataMessageStanza{{id={:?}, from={:?}, category={:?}}}",
            self.id, self.from, self.category
        )
    }
}
