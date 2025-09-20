use crate::consts::{KMCS_VERSION, K_LOGIN_REQUEST_TAG};
use crate::error::Result;
use crate::proto::put_uvarint;

use super::types::*;
use super::{
    marshal_login_request, unmarshal_close, unmarshal_data_message_stanza, unmarshal_heartbeat_ack,
    unmarshal_heartbeat_ping, unmarshal_iq_stanza, unmarshal_login_request,
    unmarshal_login_response, unmarshal_stream_error_stanza,
};

pub fn create_login_request_raw(
    android_id: u64,
    security_token: u64,
    persistent_ids: &[String],
) -> Result<Vec<u8>> {
    let chrome_version = "chrome-63.0.3234.0";
    let domain = "mcs.android.com";

    let android_id_formatted = android_id.to_string();
    let android_id_hex = format!("android-{android_id:x}");
    let security_token_formatted = security_token.to_string();

    let persistent_copy = if persistent_ids.len() > 2 {
        persistent_ids[persistent_ids.len() - 2..].to_vec()
    } else {
        persistent_ids.to_vec()
    };

    let request = ManualLoginRequest {
        id: chrome_version.to_string(),
        domain: domain.to_string(),
        user: android_id_formatted.clone(),
        resource: android_id_formatted.clone(),
        auth_token: security_token_formatted,
        device_id: android_id_hex,
        last_rmq_id: None,
        setting: vec![ManualSetting {
            name: "new_vc".to_string(),
            value: "1".to_string(),
        }],
        received_persistent_id: persistent_copy,
        adaptive_heartbeat: Some(false),
        heartbeat_stat: None,
        use_rmq2: Some(true),
        account_id: None,
        auth_service: Some(ManualLoginRequestAuthService::AndroidId),
        network_type: Some(1),
        status: None,
        client_event: Vec::new(),
    };

    let payload = marshal_login_request(&request)?;

    let mut packet = Vec::with_capacity(2 + 5 + payload.len());
    packet.push(KMCS_VERSION);
    packet.push(K_LOGIN_REQUEST_TAG);
    packet.extend_from_slice(&put_uvarint(payload.len() as u64));
    packet.extend_from_slice(&payload);
    Ok(packet)
}

pub fn create_check_in_request(
    android_id: i64,
    security_token: Option<u64>,
) -> ManualAndroidCheckinRequest {
    let mut request = ManualAndroidCheckinRequest::default();
    request.id = Some(android_id);
    request.version = Some(3);
    request.security_token = security_token;

    let chrome_build = ManualChromeBuildProto {
        platform: Some(ManualChromeBuildPlatform::Linux),
        chrome_version: Some("63.0.3234.0".to_string()),
        channel: Some(ManualChromeBuildChannel::Stable),
    };

    request.checkin = Some(ManualAndroidCheckinProto {
        last_checkin_msec: None,
        cell_operator: None,
        sim_operator: None,
        roaming: None,
        user_number: None,
        device_type: Some(ManualDeviceType::ChromeBrowser),
        chrome_build: Some(chrome_build),
    });

    request
}

pub fn decode_heartbeat_ping(data: &[u8]) -> Result<ManualHeartbeatPing> {
    unmarshal_heartbeat_ping(data)
}

pub fn decode_heartbeat_ack(data: &[u8]) -> Result<ManualHeartbeatAck> {
    unmarshal_heartbeat_ack(data)
}

pub fn decode_login_request(data: &[u8]) -> Result<ManualLoginRequest> {
    unmarshal_login_request(data)
}

pub fn decode_login_response(data: &[u8]) -> Result<ManualLoginResponse> {
    unmarshal_login_response(data)
}

pub fn decode_close(data: &[u8]) -> Result<ManualClose> {
    unmarshal_close(data)
}

pub fn decode_iq_stanza(data: &[u8]) -> Result<ManualIqStanza> {
    unmarshal_iq_stanza(data)
}

pub fn decode_data_message_stanza(data: &[u8]) -> Result<ManualDataMessageStanza> {
    unmarshal_data_message_stanza(data)
}

pub fn decode_stream_error_stanza(data: &[u8]) -> Result<ManualStreamErrorStanza> {
    unmarshal_stream_error_stanza(data)
}
