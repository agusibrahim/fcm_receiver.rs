pub const CHECK_IN_URL: &str = "https://android.clients.google.com/checkin";
pub const REGISTER_URL: &str = "https://android.clients.google.com/c2dm/register3";

pub const FIREBASE_INSTALLATION_URL: &str = "https://firebaseinstallations.googleapis.com/v1/";
pub const FIREBASE_REGISTRATION_URL: &str = "https://fcmregistrations.googleapis.com/v1/";
pub const FCM_ENDPOINT_URL: &str = "https://fcm.googleapis.com/fcm/send";
pub const FCM_SOCKET_ADDRESS: &str = "mtalk.google.com:5228";

pub const DEFAULT_FCM_MESSAGE_TTL_SECS: u64 = 60 * 60 * 24 * 28;

pub const MCS_VERSION_TAG_AND_SIZE: u8 = 0;
pub const MCS_TAG_AND_SIZE: u8 = 1;
pub const MCS_SIZE: u8 = 2;
pub const MCS_PROTO_BYTES: u8 = 3;

pub const VERSION_PACKET_LEN: usize = 1;
pub const TAG_PACKET_LEN: usize = 1;
pub const SIZE_PACKET_LEN_MIN: usize = 1;
pub const SIZE_PACKET_LEN_MAX: usize = 5;

pub const KMCS_VERSION: u8 = 41;

pub const K_HEARTBEAT_PING_TAG: u8 = 0;
pub const K_HEARTBEAT_ACK_TAG: u8 = 1;
pub const K_LOGIN_REQUEST_TAG: u8 = 2;
pub const K_LOGIN_RESPONSE_TAG: u8 = 3;
pub const K_CLOSE_TAG: u8 = 4;
pub const K_MESSAGE_STANZA_TAG: u8 = 5;
pub const K_PRESENCE_STANZA_TAG: u8 = 6;
pub const K_IQ_STANZA_TAG: u8 = 7;
pub const K_DATA_MESSAGE_STANZA_TAG: u8 = 8;
pub const K_BATCH_PRESENCE_STANZA_TAG: u8 = 9;
pub const K_STREAM_ERROR_STANZA_TAG: u8 = 10;

pub const FCM_SERVER_KEY: [u8; 65] = [
    4, 51, 148, 247, 223, 161, 235, 177, 220, 3, 162, 94, 21, 113, 219, 72, 211, 46, 237, 237, 178,
    52, 219, 183, 71, 58, 12, 143, 196, 204, 225, 111, 60, 140, 132, 223, 171, 182, 102, 62, 242,
    12, 212, 139, 254, 227, 249, 118, 47, 20, 28, 99, 8, 106, 111, 45, 177, 26, 149, 176, 206, 55,
    192, 156, 110,
];
