use std::fmt;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("proto error: {0}")]
    Proto(#[from] ProtoError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("tls error: {0}")]
    Tls(#[from] native_tls::Error),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("url error: {0}")]
    Url(#[from] url::ParseError),
    #[error("hkdf error: {0}")]
    Hkdf(String),
    #[error("crypto error: {0}")]
    Crypto(String),
    #[error("invalid data: {0}")]
    InvalidData(&'static str),
    #[error("other error: {0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtoErrorKind {
    Eof,
    InvalidVarint,
    InvalidLength,
    UnsupportedWireType(u8),
    InvalidWireType,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtoError {
    kind: ProtoErrorKind,
    context: Option<&'static str>,
}

impl ProtoError {
    pub fn new(kind: ProtoErrorKind) -> Self {
        Self {
            kind,
            context: None,
        }
    }

    pub fn with_context(kind: ProtoErrorKind, context: &'static str) -> Self {
        Self {
            kind,
            context: Some(context),
        }
    }

    pub fn kind(&self) -> &ProtoErrorKind {
        &self.kind
    }
}

impl fmt::Display for ProtoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let base = match &self.kind {
            ProtoErrorKind::Eof => "unexpected EOF".to_string(),
            ProtoErrorKind::InvalidVarint => "invalid varint encoding".to_string(),
            ProtoErrorKind::InvalidLength => "invalid length".to_string(),
            ProtoErrorKind::UnsupportedWireType(wt) => format!("unsupported wire type {wt}"),
            ProtoErrorKind::InvalidWireType => "invalid wire type".to_string(),
        };

        if let Some(ctx) = self.context {
            write!(f, "{base} ({ctx})")
        } else {
            write!(f, "{base}")
        }
    }
}

impl std::error::Error for ProtoError {}
