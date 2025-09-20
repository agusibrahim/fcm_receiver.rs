use crate::error::{Error, Result};
use crate::proto::{ProtoDecoder, WireType};

use super::types::*;

pub fn unmarshal_android_checkin_response(data: &[u8]) -> Result<ManualAndroidCheckinResponse> {
    let mut decoder = ProtoDecoder::new(data);
    let mut msg = ManualAndroidCheckinResponse::default();

    while decoder.remaining() > 0 {
        let (field_number, wire_type) = decoder.decode_field_number()?;
        match field_number {
            1 => {
                if wire_type != WireType::Varint {
                    return Err(Error::InvalidData("field 1 expects varint"));
                }
                msg.stats_ok = Some(decoder.decode_bool()?);
            }
            2 => {
                // Unknown/repeated message; skip for compatibility
                decoder.skip_field(wire_type)?;
            }
            3 => {
                if wire_type != WireType::Varint {
                    decoder.skip_field(wire_type)?;
                } else {
                    msg.time_msec = Some(decoder.decode_int64()?);
                }
            }
            4 => {
                if wire_type == WireType::LengthDelimited {
                    msg.digest = Some(decoder.decode_string()?);
                } else {
                    decoder.skip_field(wire_type)?;
                }
            }
            5 => {
                if wire_type == WireType::LengthDelimited {
                    let bytes = decoder.decode_bytes()?;
                    let setting = unmarshal_gservices_setting(bytes)?;
                    msg.setting.push(setting);
                } else {
                    decoder.skip_field(wire_type)?;
                }
            }
            6 => {
                if wire_type == WireType::Varint {
                    msg.market_ok = Some(decoder.decode_bool()?);
                } else {
                    decoder.skip_field(wire_type)?;
                }
            }
            7 => match wire_type {
                WireType::Bit64 => {
                    msg.android_id = Some(decoder.decode_fixed64()?);
                }
                WireType::Varint => {
                    msg.android_id = Some(decoder.decode_uint64()?);
                }
                _ => decoder.skip_field(wire_type)?,
            },
            8 => match wire_type {
                WireType::Bit64 => {
                    msg.security_token = Some(decoder.decode_fixed64()?);
                }
                WireType::Varint => {
                    msg.security_token = Some(decoder.decode_uint64()?);
                }
                _ => decoder.skip_field(wire_type)?,
            },
            9 => {
                if wire_type == WireType::Varint {
                    msg.settings_diff = Some(decoder.decode_bool()?);
                } else {
                    decoder.skip_field(wire_type)?;
                }
            }
            10 => {
                if wire_type == WireType::LengthDelimited {
                    msg.delete_setting.push(decoder.decode_string()?);
                } else {
                    decoder.skip_field(wire_type)?;
                }
            }
            11 => {
                if wire_type == WireType::LengthDelimited {
                    msg.version_info = Some(decoder.decode_string()?);
                } else {
                    decoder.skip_field(wire_type)?;
                }
            }
            _ => decoder.skip_field(wire_type)?,
        }
    }

    Ok(msg)
}

fn unmarshal_gservices_setting(data: &[u8]) -> Result<ManualGservicesSetting> {
    let mut decoder = ProtoDecoder::new(data);
    let mut setting = ManualGservicesSetting::default();
    while decoder.remaining() > 0 {
        let (field, wire_type) = decoder.decode_field_number()?;
        match field {
            1 => {
                if wire_type != WireType::LengthDelimited {
                    return Err(Error::InvalidData("field 1 expects bytes"));
                }
                setting.name = decoder.decode_bytes()?.to_vec();
            }
            2 => {
                if wire_type != WireType::LengthDelimited {
                    return Err(Error::InvalidData("field 2 expects bytes"));
                }
                setting.value = decoder.decode_bytes()?.to_vec();
            }
            _ => decoder.skip_field(wire_type)?,
        }
    }
    Ok(setting)
}

pub fn unmarshal_heartbeat_ping(data: &[u8]) -> Result<ManualHeartbeatPing> {
    let mut decoder = ProtoDecoder::new(data);
    let mut msg = ManualHeartbeatPing::default();
    while decoder.remaining() > 0 {
        let (field, wire_type) = decoder.decode_field_number()?;
        match field {
            1 => {
                msg.stream_id = Some(decoder.decode_int32()?);
            }
            2 => {
                msg.last_stream_id_received = Some(decoder.decode_int32()?);
            }
            3 => {
                msg.status = Some(decoder.decode_int64()?);
            }
            _ => decoder.skip_field(wire_type)?,
        }
    }
    Ok(msg)
}

pub fn unmarshal_heartbeat_ack(data: &[u8]) -> Result<ManualHeartbeatAck> {
    let mut decoder = ProtoDecoder::new(data);
    let mut msg = ManualHeartbeatAck::default();
    while decoder.remaining() > 0 {
        let (field, wire_type) = decoder.decode_field_number()?;
        match field {
            1 => {
                msg.stream_id = Some(decoder.decode_int32()?);
            }
            2 => {
                msg.last_stream_id_received = Some(decoder.decode_int32()?);
            }
            3 => {
                msg.status = Some(decoder.decode_int64()?);
            }
            _ => decoder.skip_field(wire_type)?,
        }
    }
    Ok(msg)
}

pub fn unmarshal_setting(data: &[u8]) -> Result<ManualSetting> {
    let mut decoder = ProtoDecoder::new(data);
    let mut setting = ManualSetting::default();
    while decoder.remaining() > 0 {
        let (field, wire_type) = decoder.decode_field_number()?;
        match field {
            1 => {
                setting.name = decoder.decode_string()?;
            }
            2 => {
                setting.value = decoder.decode_string()?;
            }
            _ => decoder.skip_field(wire_type)?,
        }
    }
    Ok(setting)
}

pub fn unmarshal_heartbeat_stat(data: &[u8]) -> Result<ManualHeartbeatStat> {
    let mut decoder = ProtoDecoder::new(data);
    let mut stat = ManualHeartbeatStat::default();
    while decoder.remaining() > 0 {
        let (field, wire_type) = decoder.decode_field_number()?;
        match field {
            1 => stat.ip = Some(decoder.decode_string()?),
            2 => stat.timeout = Some(decoder.decode_bool()?),
            3 => stat.interval_ms = Some(decoder.decode_int32()?),
            _ => decoder.skip_field(wire_type)?,
        }
    }
    Ok(stat)
}

pub fn unmarshal_client_event(data: &[u8]) -> Result<ManualClientEvent> {
    let mut decoder = ProtoDecoder::new(data);
    let mut event = ManualClientEvent::default();
    while decoder.remaining() > 0 {
        let (field, wire_type) = decoder.decode_field_number()?;
        match field {
            1 => {
                let value = decoder.decode_int32()?;
                event.event_type = Some(match value {
                    0 => ManualClientEventType::Unknown,
                    1 => ManualClientEventType::UnvisitMcs,
                    _ => ManualClientEventType::Unknown,
                });
            }
            100 => event.number_discarded_events = Some(decoder.decode_uint32()?),
            200 => event.network_type = Some(decoder.decode_int32()?),
            202 => event.time_connection_started_ms = Some(decoder.decode_uint64()?),
            203 => event.time_connection_ended_ms = Some(decoder.decode_uint64()?),
            204 => event.error_code = Some(decoder.decode_int32()?),
            300 => event.time_connection_established_ms = Some(decoder.decode_uint64()?),
            _ => decoder.skip_field(wire_type)?,
        }
    }
    Ok(event)
}

pub fn unmarshal_android_checkin_proto(data: &[u8]) -> Result<ManualAndroidCheckinProto> {
    let mut decoder = ProtoDecoder::new(data);
    let mut msg = ManualAndroidCheckinProto::default();
    while decoder.remaining() > 0 {
        let (field, wire_type) = decoder.decode_field_number()?;
        match field {
            2 => msg.last_checkin_msec = Some(decoder.decode_int64()?),
            6 => msg.cell_operator = Some(decoder.decode_string()?),
            7 => msg.sim_operator = Some(decoder.decode_string()?),
            8 => msg.roaming = Some(decoder.decode_string()?),
            9 => msg.user_number = Some(decoder.decode_int32()?),
            12 => {
                let val = decoder.decode_int32()?;
                msg.device_type = Some(match val {
                    1 => ManualDeviceType::AndroidOs,
                    2 => ManualDeviceType::IosOs,
                    3 => ManualDeviceType::ChromeBrowser,
                    4 => ManualDeviceType::ChromeOs,
                    _ => ManualDeviceType::AndroidOs,
                });
            }
            13 => {
                let bytes = decoder.decode_bytes()?;
                msg.chrome_build = Some(unmarshal_chrome_build_proto(bytes)?);
            }
            _ => decoder.skip_field(wire_type)?,
        }
    }
    Ok(msg)
}

pub fn unmarshal_chrome_build_proto(data: &[u8]) -> Result<ManualChromeBuildProto> {
    let mut decoder = ProtoDecoder::new(data);
    let mut msg = ManualChromeBuildProto::default();
    while decoder.remaining() > 0 {
        let (field, wire_type) = decoder.decode_field_number()?;
        match field {
            1 => {
                let val = decoder.decode_int32()?;
                msg.platform = Some(match val {
                    1 => ManualChromeBuildPlatform::Win,
                    2 => ManualChromeBuildPlatform::Mac,
                    3 => ManualChromeBuildPlatform::Linux,
                    4 => ManualChromeBuildPlatform::Cros,
                    5 => ManualChromeBuildPlatform::Ios,
                    6 => ManualChromeBuildPlatform::Android,
                    _ => ManualChromeBuildPlatform::Linux,
                });
            }
            2 => msg.chrome_version = Some(decoder.decode_string()?),
            3 => {
                let val = decoder.decode_int32()?;
                msg.channel = Some(match val {
                    1 => ManualChromeBuildChannel::Stable,
                    2 => ManualChromeBuildChannel::Beta,
                    3 => ManualChromeBuildChannel::Dev,
                    4 => ManualChromeBuildChannel::Canary,
                    5 => ManualChromeBuildChannel::Unknown,
                    _ => ManualChromeBuildChannel::Stable,
                });
            }
            _ => decoder.skip_field(wire_type)?,
        }
    }
    Ok(msg)
}

pub fn unmarshal_login_request(data: &[u8]) -> Result<ManualLoginRequest> {
    let mut decoder = ProtoDecoder::new(data);
    let mut msg = ManualLoginRequest::default();
    while decoder.remaining() > 0 {
        let (field, wire_type) = decoder.decode_field_number()?;
        match field {
            1 => msg.id = decoder.decode_string()?,
            2 => msg.domain = decoder.decode_string()?,
            3 => msg.user = decoder.decode_string()?,
            4 => msg.resource = decoder.decode_string()?,
            5 => msg.auth_token = decoder.decode_string()?,
            6 => msg.device_id = decoder.decode_string()?,
            7 => msg.last_rmq_id = Some(decoder.decode_int64()?),
            8 => {
                let bytes = decoder.decode_bytes()?;
                msg.setting.push(unmarshal_setting(bytes)?);
            }
            10 => msg.received_persistent_id.push(decoder.decode_string()?),
            12 => msg.adaptive_heartbeat = Some(decoder.decode_bool()?),
            13 => {
                let bytes = decoder.decode_bytes()?;
                msg.heartbeat_stat = Some(unmarshal_heartbeat_stat(bytes)?);
            }
            14 => msg.use_rmq2 = Some(decoder.decode_bool()?),
            15 => msg.account_id = Some(decoder.decode_int64()?),
            16 => {
                let val = decoder.decode_int32()?;
                msg.auth_service = Some(match val {
                    2 => ManualLoginRequestAuthService::AndroidId,
                    _ => ManualLoginRequestAuthService::AndroidId,
                });
            }
            17 => msg.network_type = Some(decoder.decode_int32()?),
            18 => msg.status = Some(decoder.decode_int64()?),
            22 => {
                let bytes = decoder.decode_bytes()?;
                msg.client_event.push(unmarshal_client_event(bytes)?);
            }
            _ => decoder.skip_field(wire_type)?,
        }
    }
    Ok(msg)
}

pub fn unmarshal_login_response(data: &[u8]) -> Result<ManualLoginResponse> {
    let mut decoder = ProtoDecoder::new(data);
    let mut msg = ManualLoginResponse::default();
    while decoder.remaining() > 0 {
        let (field, wire_type) = decoder.decode_field_number()?;
        match field {
            1 => msg.id = Some(decoder.decode_string()?),
            2 => msg.jid = Some(decoder.decode_string()?),
            3 => {
                let bytes = decoder.decode_bytes()?;
                msg.error = Some(unmarshal_error_info(bytes)?);
            }
            5 => {
                let bytes = decoder.decode_bytes()?;
                msg.setting.push(unmarshal_setting(bytes)?);
            }
            7 => msg.stream_id = Some(decoder.decode_int32()?),
            8 => msg.last_stream_id_received = Some(decoder.decode_int32()?),
            9 => {
                let bytes = decoder.decode_bytes()?;
                msg.heartbeat_config = Some(unmarshal_heartbeat_config(bytes)?);
            }
            10 => msg.server_timestamp = Some(decoder.decode_int64()?),
            _ => decoder.skip_field(wire_type)?,
        }
    }
    Ok(msg)
}

pub fn unmarshal_error_info(data: &[u8]) -> Result<ManualErrorInfo> {
    let mut decoder = ProtoDecoder::new(data);
    let mut msg = ManualErrorInfo::default();
    while decoder.remaining() > 0 {
        let (field, wire_type) = decoder.decode_field_number()?;
        match field {
            1 => msg.code = Some(decoder.decode_int32()?),
            2 => msg.message = Some(decoder.decode_string()?),
            3 => msg.error_type = Some(decoder.decode_string()?),
            4 => {
                let bytes = decoder.decode_bytes()?;
                msg.extension = Some(unmarshal_extension(bytes)?);
            }
            _ => decoder.skip_field(wire_type)?,
        }
    }
    Ok(msg)
}

pub fn unmarshal_extension(data: &[u8]) -> Result<ManualExtension> {
    let mut decoder = ProtoDecoder::new(data);
    let mut msg = ManualExtension::default();
    while decoder.remaining() > 0 {
        let (field, wire_type) = decoder.decode_field_number()?;
        match field {
            1 => msg.id = Some(decoder.decode_int32()?),
            2 => msg.data = decoder.decode_bytes()?.to_vec(),
            _ => decoder.skip_field(wire_type)?,
        }
    }
    Ok(msg)
}

pub fn unmarshal_heartbeat_config(data: &[u8]) -> Result<ManualHeartbeatConfig> {
    let mut decoder = ProtoDecoder::new(data);
    let mut msg = ManualHeartbeatConfig::default();
    while decoder.remaining() > 0 {
        let (field, wire_type) = decoder.decode_field_number()?;
        match field {
            1 => msg.upload_stat = Some(decoder.decode_bool()?),
            2 => msg.ip = Some(decoder.decode_string()?),
            3 => msg.interval_ms = Some(decoder.decode_int32()?),
            _ => decoder.skip_field(wire_type)?,
        }
    }
    Ok(msg)
}

pub fn unmarshal_close(_data: &[u8]) -> Result<ManualClose> {
    Ok(ManualClose)
}

pub fn unmarshal_iq_stanza(data: &[u8]) -> Result<ManualIqStanza> {
    let mut decoder = ProtoDecoder::new(data);
    let mut msg = ManualIqStanza::default();
    while decoder.remaining() > 0 {
        let (field, wire_type) = decoder.decode_field_number()?;
        match field {
            1 => msg.rmq_id = Some(decoder.decode_int64()?),
            2 => {
                let raw = decoder.decode_int32()?;
                msg.stanza_type = Some(match raw {
                    0 => ManualIqStanzaType::Get,
                    1 => ManualIqStanzaType::Set,
                    2 => ManualIqStanzaType::Result,
                    3 => ManualIqStanzaType::Error,
                    _ => ManualIqStanzaType::Get,
                });
            }
            3 => msg.id = Some(decoder.decode_string()?),
            4 => msg.from = Some(decoder.decode_string()?),
            5 => msg.to = Some(decoder.decode_string()?),
            6 => {
                let bytes = decoder.decode_bytes()?;
                msg.error = Some(unmarshal_error_info(bytes)?);
            }
            7 => {
                let bytes = decoder.decode_bytes()?;
                msg.extension = Some(unmarshal_extension(bytes)?);
            }
            8 => msg.persistent_id = Some(decoder.decode_string()?),
            9 => msg.stream_id = Some(decoder.decode_int32()?),
            10 => msg.last_stream_id_received = Some(decoder.decode_int32()?),
            12 => msg.account_id = Some(decoder.decode_int64()?),
            13 => msg.status = Some(decoder.decode_int64()?),
            _ => decoder.skip_field(wire_type)?,
        }
    }
    Ok(msg)
}

pub fn unmarshal_data_message_stanza(data: &[u8]) -> Result<ManualDataMessageStanza> {
    let mut decoder = ProtoDecoder::new(data);
    let mut msg = ManualDataMessageStanza::default();
    while decoder.remaining() > 0 {
        let (field, wire_type) = decoder.decode_field_number()?;
        match field {
            2 => msg.id = Some(decoder.decode_string()?),
            3 => msg.from = Some(decoder.decode_string()?),
            4 => msg.to = Some(decoder.decode_string()?),
            5 => msg.category = Some(decoder.decode_string()?),
            6 => msg.token = Some(decoder.decode_string()?),
            7 => {
                let bytes = decoder.decode_bytes()?;
                msg.app_data.push(unmarshal_app_data(bytes)?);
            }
            8 => msg.from_trusted_server = Some(decoder.decode_bool()?),
            9 => msg.persistent_id = Some(decoder.decode_string()?),
            10 => msg.stream_id = Some(decoder.decode_int32()?),
            11 => msg.last_stream_id_received = Some(decoder.decode_int32()?),
            13 => msg.reg_id = Some(decoder.decode_string()?),
            16 => msg.device_user_id = Some(decoder.decode_int64()?),
            17 => msg.ttl = Some(decoder.decode_int32()?),
            18 => msg.sent = Some(decoder.decode_int64()?),
            19 => msg.queued = Some(decoder.decode_int32()?),
            20 => msg.status = Some(decoder.decode_int64()?),
            21 => msg.raw_data = Some(decoder.decode_bytes()?.to_vec()),
            24 => msg.immediate_ack = Some(decoder.decode_bool()?),
            _ => decoder.skip_field(wire_type)?,
        }
    }
    Ok(msg)
}

pub fn unmarshal_app_data(data: &[u8]) -> Result<ManualAppData> {
    let mut decoder = ProtoDecoder::new(data);
    let mut msg = ManualAppData::default();
    while decoder.remaining() > 0 {
        let (field, wire_type) = decoder.decode_field_number()?;
        match field {
            1 => msg.key = decoder.decode_string()?,
            2 => msg.value = decoder.decode_string()?,
            _ => decoder.skip_field(wire_type)?,
        }
    }
    Ok(msg)
}

pub fn unmarshal_stream_error_stanza(data: &[u8]) -> Result<ManualStreamErrorStanza> {
    let mut decoder = ProtoDecoder::new(data);
    let mut msg = ManualStreamErrorStanza::default();
    while decoder.remaining() > 0 {
        let (field, wire_type) = decoder.decode_field_number()?;
        match field {
            1 => msg.error_type = Some(decoder.decode_string()?),
            2 => msg.text = Some(decoder.decode_string()?),
            _ => decoder.skip_field(wire_type)?,
        }
    }
    Ok(msg)
}
