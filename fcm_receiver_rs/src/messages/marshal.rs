use crate::error::Result;
use crate::proto::ProtoEncoder;

use super::types::*;

pub fn marshal_android_checkin_request(msg: &ManualAndroidCheckinRequest) -> Result<Vec<u8>> {
    let mut encoder = ProtoEncoder::new();

    if let Some(imei) = &msg.imei {
        encoder.encode_string(1, imei);
    }
    if let Some(meid) = &msg.meid {
        encoder.encode_string(10, meid);
    }
    for addr in &msg.mac_addr {
        encoder.encode_string(9, addr);
    }
    for addr_type in &msg.mac_addr_type {
        encoder.encode_string(19, addr_type);
    }
    if let Some(serial) = &msg.serial_number {
        encoder.encode_string(16, serial);
    }
    if let Some(esn) = &msg.esn {
        encoder.encode_string(17, esn);
    }
    if let Some(id) = msg.id {
        encoder.encode_int64(2, id);
    }
    if let Some(logging_id) = msg.logging_id {
        encoder.encode_int64(7, logging_id);
    }
    if let Some(digest) = &msg.digest {
        encoder.encode_string(3, digest);
    }
    if let Some(locale) = &msg.locale {
        encoder.encode_string(6, locale);
    }
    if let Some(checkin) = &msg.checkin {
        let bytes = marshal_android_checkin_proto(checkin)?;
        encoder.encode_bytes(4, &bytes);
    }
    if let Some(desired) = &msg.desired_build {
        encoder.encode_string(5, desired);
    }
    if let Some(market) = &msg.market_checkin {
        encoder.encode_string(8, market);
    }
    for cookie in &msg.account_cookie {
        encoder.encode_string(11, cookie);
    }
    if let Some(tz) = &msg.time_zone {
        encoder.encode_string(12, tz);
    }
    if let Some(token) = msg.security_token {
        encoder.encode_fixed64(13, token);
    }
    if let Some(version) = msg.version {
        encoder.encode_int32(14, version);
    }
    for cert in &msg.ota_cert {
        encoder.encode_string(15, cert);
    }
    if let Some(fragment) = msg.fragment {
        encoder.encode_int32(20, fragment);
    }
    if let Some(user_name) = &msg.user_name {
        encoder.encode_string(21, user_name);
    }
    if let Some(serial) = msg.user_serial_number {
        encoder.encode_int32(22, serial);
    }

    Ok(encoder.into_bytes())
}

pub fn marshal_android_checkin_proto(msg: &ManualAndroidCheckinProto) -> Result<Vec<u8>> {
    let mut encoder = ProtoEncoder::new();

    if let Some(last) = msg.last_checkin_msec {
        encoder.encode_int64(2, last);
    }
    if let Some(cell) = &msg.cell_operator {
        encoder.encode_string(6, cell);
    }
    if let Some(sim) = &msg.sim_operator {
        encoder.encode_string(7, sim);
    }
    if let Some(roaming) = &msg.roaming {
        encoder.encode_string(8, roaming);
    }
    if let Some(user_number) = msg.user_number {
        encoder.encode_int32(9, user_number);
    }
    if let Some(device_type) = msg.device_type {
        encoder.encode_int32(12, device_type as i32);
    }
    if let Some(chrome) = &msg.chrome_build {
        let bytes = marshal_chrome_build_proto(chrome)?;
        encoder.encode_bytes(13, &bytes);
    }

    Ok(encoder.into_bytes())
}

pub fn marshal_chrome_build_proto(msg: &ManualChromeBuildProto) -> Result<Vec<u8>> {
    let mut encoder = ProtoEncoder::new();

    if let Some(platform) = msg.platform {
        encoder.encode_int32(1, platform as i32);
    }
    if let Some(version) = &msg.chrome_version {
        encoder.encode_string(2, version);
    }
    if let Some(channel) = msg.channel {
        encoder.encode_int32(3, channel as i32);
    }

    Ok(encoder.into_bytes())
}

pub fn marshal_login_request(msg: &ManualLoginRequest) -> Result<Vec<u8>> {
    let mut encoder = ProtoEncoder::new();

    encoder.encode_string(1, &msg.id);
    encoder.encode_string(2, &msg.domain);
    encoder.encode_string(3, &msg.user);
    encoder.encode_string(4, &msg.resource);
    encoder.encode_string(5, &msg.auth_token);
    encoder.encode_string(6, &msg.device_id);

    if let Some(last_rmq) = msg.last_rmq_id {
        encoder.encode_int64(7, last_rmq);
    }

    for setting in &msg.setting {
        let bytes = marshal_setting(setting)?;
        encoder.encode_bytes(8, &bytes);
    }

    for id in &msg.received_persistent_id {
        encoder.encode_string(10, id);
    }

    if let Some(adaptive) = msg.adaptive_heartbeat {
        encoder.encode_bool(12, adaptive);
    }

    if let Some(stat) = &msg.heartbeat_stat {
        let bytes = marshal_heartbeat_stat(stat)?;
        encoder.encode_bytes(13, &bytes);
    }

    if let Some(use_rmq2) = msg.use_rmq2 {
        encoder.encode_bool(14, use_rmq2);
    }

    if let Some(account_id) = msg.account_id {
        encoder.encode_int64(15, account_id);
    }

    if let Some(auth_service) = msg.auth_service {
        encoder.encode_int32(16, auth_service as i32);
    }

    if let Some(network_type) = msg.network_type {
        encoder.encode_int32(17, network_type);
    }

    if let Some(status) = msg.status {
        encoder.encode_int64(18, status);
    }

    for event in &msg.client_event {
        let bytes = marshal_client_event(event)?;
        encoder.encode_bytes(22, &bytes);
    }

    Ok(encoder.into_bytes())
}

pub fn marshal_setting(msg: &ManualSetting) -> Result<Vec<u8>> {
    let mut encoder = ProtoEncoder::new();
    encoder.encode_string(1, &msg.name);
    encoder.encode_string(2, &msg.value);
    Ok(encoder.into_bytes())
}

pub fn marshal_heartbeat_stat(msg: &ManualHeartbeatStat) -> Result<Vec<u8>> {
    let mut encoder = ProtoEncoder::new();
    if let Some(ip) = &msg.ip {
        encoder.encode_string(1, ip);
    }
    if let Some(timeout) = msg.timeout {
        encoder.encode_bool(2, timeout);
    }
    if let Some(interval) = msg.interval_ms {
        encoder.encode_int32(3, interval);
    }
    Ok(encoder.into_bytes())
}

pub fn marshal_client_event(msg: &ManualClientEvent) -> Result<Vec<u8>> {
    let mut encoder = ProtoEncoder::new();
    if let Some(event_type) = msg.event_type {
        encoder.encode_int32(1, event_type as i32);
    }
    if let Some(discarded) = msg.number_discarded_events {
        encoder.encode_uint32(100, discarded);
    }
    if let Some(network_type) = msg.network_type {
        encoder.encode_int32(200, network_type);
    }
    if let Some(started) = msg.time_connection_started_ms {
        encoder.encode_uint64(202, started);
    }
    if let Some(ended) = msg.time_connection_ended_ms {
        encoder.encode_uint64(203, ended);
    }
    if let Some(error_code) = msg.error_code {
        encoder.encode_int32(204, error_code);
    }
    if let Some(established) = msg.time_connection_established_ms {
        encoder.encode_uint64(300, established);
    }
    Ok(encoder.into_bytes())
}

pub fn marshal_data_message_stanza(msg: &ManualDataMessageStanza) -> Result<Vec<u8>> {
    let mut encoder = ProtoEncoder::new();

    if let Some(id) = &msg.id {
        encoder.encode_string(2, id);
    }
    if let Some(from) = &msg.from {
        encoder.encode_string(3, from);
    }
    if let Some(to) = &msg.to {
        encoder.encode_string(4, to);
    }
    if let Some(category) = &msg.category {
        encoder.encode_string(5, category);
    }
    if let Some(token) = &msg.token {
        encoder.encode_string(6, token);
    }
    for app_data in &msg.app_data {
        let bytes = marshal_app_data(app_data)?;
        encoder.encode_bytes(7, &bytes);
    }
    if let Some(from_trusted) = msg.from_trusted_server {
        encoder.encode_bool(8, from_trusted);
    }
    if let Some(pid) = &msg.persistent_id {
        encoder.encode_string(9, pid);
    }
    if let Some(stream_id) = msg.stream_id {
        encoder.encode_int32(10, stream_id);
    }
    if let Some(last_stream) = msg.last_stream_id_received {
        encoder.encode_int32(11, last_stream);
    }
    if let Some(reg_id) = &msg.reg_id {
        encoder.encode_string(13, reg_id);
    }
    if let Some(device_user_id) = msg.device_user_id {
        encoder.encode_int64(16, device_user_id);
    }
    if let Some(ttl) = msg.ttl {
        encoder.encode_int32(17, ttl);
    }
    if let Some(sent) = msg.sent {
        encoder.encode_int64(18, sent);
    }
    if let Some(queued) = msg.queued {
        encoder.encode_int32(19, queued);
    }
    if let Some(status) = msg.status {
        encoder.encode_int64(20, status);
    }
    if let Some(raw) = &msg.raw_data {
        encoder.encode_bytes(21, raw);
    }
    if let Some(immediate_ack) = msg.immediate_ack {
        encoder.encode_bool(24, immediate_ack);
    }

    Ok(encoder.into_bytes())
}

pub fn marshal_app_data(msg: &ManualAppData) -> Result<Vec<u8>> {
    let mut encoder = ProtoEncoder::new();
    encoder.encode_string(1, &msg.key);
    encoder.encode_string(2, &msg.value);
    Ok(encoder.into_bytes())
}

pub fn marshal_heartbeat_ping(msg: &ManualHeartbeatPing) -> Result<Vec<u8>> {
    let mut encoder = ProtoEncoder::new();
    if let Some(stream_id) = msg.stream_id {
        encoder.encode_int32(1, stream_id);
    }
    if let Some(last_stream) = msg.last_stream_id_received {
        encoder.encode_int32(2, last_stream);
    }
    if let Some(status) = msg.status {
        encoder.encode_int64(3, status);
    }
    Ok(encoder.into_bytes())
}

pub fn marshal_heartbeat_ack(msg: &ManualHeartbeatAck) -> Result<Vec<u8>> {
    let mut encoder = ProtoEncoder::new();
    if let Some(stream_id) = msg.stream_id {
        encoder.encode_int32(1, stream_id);
    }
    if let Some(last_stream) = msg.last_stream_id_received {
        encoder.encode_int32(2, last_stream);
    }
    if let Some(status) = msg.status {
        encoder.encode_int64(3, status);
    }
    Ok(encoder.into_bytes())
}

pub fn marshal_login_response(msg: &ManualLoginResponse) -> Result<Vec<u8>> {
    let mut encoder = ProtoEncoder::new();
    if let Some(id) = &msg.id {
        encoder.encode_string(1, id);
    }
    if let Some(jid) = &msg.jid {
        encoder.encode_string(2, jid);
    }
    if let Some(error) = &msg.error {
        let bytes = marshal_error_info(error)?;
        encoder.encode_bytes(3, &bytes);
    }
    for setting in &msg.setting {
        let bytes = marshal_setting(setting)?;
        encoder.encode_bytes(5, &bytes);
    }
    if let Some(stream_id) = msg.stream_id {
        encoder.encode_int32(7, stream_id);
    }
    if let Some(last_stream) = msg.last_stream_id_received {
        encoder.encode_int32(8, last_stream);
    }
    if let Some(heartbeat) = &msg.heartbeat_config {
        let bytes = marshal_heartbeat_config(heartbeat)?;
        encoder.encode_bytes(9, &bytes);
    }
    if let Some(server_ts) = msg.server_timestamp {
        encoder.encode_int64(10, server_ts);
    }
    Ok(encoder.into_bytes())
}

pub fn marshal_error_info(msg: &ManualErrorInfo) -> Result<Vec<u8>> {
    let mut encoder = ProtoEncoder::new();
    if let Some(code) = msg.code {
        encoder.encode_int32(1, code);
    }
    if let Some(message) = &msg.message {
        encoder.encode_string(2, message);
    }
    if let Some(t) = &msg.error_type {
        encoder.encode_string(3, t);
    }
    if let Some(ext) = &msg.extension {
        let bytes = marshal_extension(ext)?;
        encoder.encode_bytes(4, &bytes);
    }
    Ok(encoder.into_bytes())
}

pub fn marshal_extension(msg: &ManualExtension) -> Result<Vec<u8>> {
    let mut encoder = ProtoEncoder::new();
    if let Some(id) = msg.id {
        encoder.encode_int32(1, id);
    }
    if !msg.data.is_empty() {
        encoder.encode_bytes(2, &msg.data);
    }
    Ok(encoder.into_bytes())
}

pub fn marshal_heartbeat_config(msg: &ManualHeartbeatConfig) -> Result<Vec<u8>> {
    let mut encoder = ProtoEncoder::new();
    if let Some(upload) = msg.upload_stat {
        encoder.encode_bool(1, upload);
    }
    if let Some(ip) = &msg.ip {
        encoder.encode_string(2, ip);
    }
    if let Some(interval) = msg.interval_ms {
        encoder.encode_int32(3, interval);
    }
    Ok(encoder.into_bytes())
}

pub fn marshal_close(_: &ManualClose) -> Result<Vec<u8>> {
    Ok(Vec::new())
}

pub fn marshal_iq_stanza(msg: &ManualIqStanza) -> Result<Vec<u8>> {
    let mut encoder = ProtoEncoder::new();
    if let Some(rmq) = msg.rmq_id {
        encoder.encode_int64(1, rmq);
    }
    if let Some(stanza_type) = msg.stanza_type {
        encoder.encode_int32(2, stanza_type as i32);
    }
    if let Some(id) = &msg.id {
        encoder.encode_string(3, id);
    }
    if let Some(from) = &msg.from {
        encoder.encode_string(4, from);
    }
    if let Some(to) = &msg.to {
        encoder.encode_string(5, to);
    }
    if let Some(error) = &msg.error {
        let bytes = marshal_error_info(error)?;
        encoder.encode_bytes(6, &bytes);
    }
    if let Some(extension) = &msg.extension {
        let bytes = marshal_extension(extension)?;
        encoder.encode_bytes(7, &bytes);
    }
    if let Some(pid) = &msg.persistent_id {
        encoder.encode_string(8, pid);
    }
    if let Some(stream_id) = msg.stream_id {
        encoder.encode_int32(9, stream_id);
    }
    if let Some(last_stream) = msg.last_stream_id_received {
        encoder.encode_int32(10, last_stream);
    }
    if let Some(account_id) = msg.account_id {
        encoder.encode_int64(12, account_id);
    }
    if let Some(status) = msg.status {
        encoder.encode_int64(13, status);
    }
    Ok(encoder.into_bytes())
}

pub fn marshal_stream_error_stanza(msg: &ManualStreamErrorStanza) -> Result<Vec<u8>> {
    let mut encoder = ProtoEncoder::new();
    if let Some(t) = &msg.error_type {
        encoder.encode_string(1, t);
    }
    if let Some(text) = &msg.text {
        encoder.encode_string(2, text);
    }
    Ok(encoder.into_bytes())
}
