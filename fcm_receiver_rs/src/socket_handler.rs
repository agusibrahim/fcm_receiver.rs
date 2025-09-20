use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::consts::*;
use crate::error::{Error, Result};
use native_tls::{TlsConnector, TlsStream};

pub struct SocketHandler {
    socket: Option<TlsStream<TcpStream>>,
    heartbeat_interval: Duration,
    on_message: Option<Arc<dyn Fn(u8, Vec<u8>) -> Result<()> + Send + Sync>>,
    buffer: Vec<u8>,
    state: u8,
    message_tag: u8,
    message_size: usize,
    last_heartbeat: Instant,
}

impl SocketHandler {
    pub fn new() -> Self {
        Self {
            socket: None,
            heartbeat_interval: Duration::from_secs(600),
            on_message: None,
            buffer: Vec::new(),
            state: MCS_VERSION_TAG_AND_SIZE,
            message_tag: 0,
            message_size: 0,
            last_heartbeat: Instant::now(),
        }
    }

    pub fn connect(&mut self) -> Result<()> {
        let connector = TlsConnector::new()
            .map_err(|e| Error::Other(format!("Failed to create TLS connector: {}", e)))?;

        let stream = TcpStream::connect(FCM_SOCKET_ADDRESS).map_err(|e| {
            Error::Other(format!(
                "Failed to connect to {}: {}",
                FCM_SOCKET_ADDRESS, e
            ))
        })?;

        stream
            .set_nodelay(true)
            .map_err(|e| Error::Other(format!("Failed to set TCP_NODELAY: {}", e)))?;

        let tls_stream = connector
            .connect("mtalk.google.com", stream)
            .map_err(|e| Error::Other(format!("Failed to establish TLS connection: {}", e)))?;

        self.socket = Some(tls_stream);
        self.init();

        Ok(())
    }

    pub fn start_socket_handler(&mut self) -> Result<()> {
        loop {
            while self.process_state_step()? {}
            self.maybe_send_periodic_heartbeat()?;
            self.read_from_socket()?;
        }
    }

    fn read_from_socket(&mut self) -> Result<()> {
        let mut buffer = [0u8; 32 * 1024];
        let socket = self.socket_mut()?;
        let bytes_read = socket
            .read(&mut buffer)
            .map_err(|e| Error::Other(format!("Failed to read from socket: {}", e)))?;

        if bytes_read == 0 {
            return Err(Error::Other("Connection closed by peer".to_string()));
        }

        self.buffer.extend_from_slice(&buffer[..bytes_read]);
        Ok(())
    }

    fn process_state_step(&mut self) -> Result<bool> {
        match self.state {
            MCS_VERSION_TAG_AND_SIZE => {
                if self.buffer.len() < VERSION_PACKET_LEN {
                    return Ok(false);
                }
                let version = self.buffer.remove(0);
                if version < KMCS_VERSION && version != 38 {
                    return Err(Error::Other(format!("Invalid version: {}", version)));
                }
                self.state = MCS_TAG_AND_SIZE;
                Ok(true)
            }
            MCS_TAG_AND_SIZE => {
                if self.buffer.len() < TAG_PACKET_LEN {
                    return Ok(false);
                }
                self.message_tag = self.buffer.remove(0);
                self.state = MCS_SIZE;
                Ok(true)
            }
            MCS_SIZE => match Self::try_read_varint(&self.buffer)? {
                Some((size, consumed)) => {
                    self.buffer.drain(0..consumed);
                    self.message_size = size;
                    if self.message_size == 0 {
                        self.dispatch_message(Vec::new())?;
                        self.state = MCS_TAG_AND_SIZE;
                    } else {
                        self.state = MCS_PROTO_BYTES;
                    }
                    Ok(true)
                }
                None => Ok(false),
            },
            MCS_PROTO_BYTES => {
                if self.buffer.len() < self.message_size {
                    return Ok(false);
                }
                let payload: Vec<u8> = self.buffer.drain(0..self.message_size).collect();
                self.dispatch_message(payload)?;
                self.state = MCS_TAG_AND_SIZE;
                Ok(true)
            }
            _ => Err(Error::Other(format!(
                "Socket handler reached unexpected state ({})",
                self.state
            ))),
        }
    }

    fn dispatch_message(&mut self, payload: Vec<u8>) -> Result<()> {
        if self.message_tag == K_HEARTBEAT_PING_TAG {
            self.send_heartbeat_ping()?;
        }

        if let Some(ref callback) = self.on_message {
            callback(self.message_tag, payload)?;
        }

        self.message_tag = 0;
        self.message_size = 0;
        Ok(())
    }

    fn maybe_send_periodic_heartbeat(&mut self) -> Result<()> {
        if self.heartbeat_interval.as_secs() == 0 {
            return Ok(());
        }

        if self.last_heartbeat.elapsed() >= self.heartbeat_interval {
            self.send_heartbeat_ping()?;
            self.last_heartbeat = Instant::now();
        }

        Ok(())
    }

    fn socket_mut(&mut self) -> Result<&mut TlsStream<TcpStream>> {
        self.socket
            .as_mut()
            .ok_or_else(|| Error::Other("Socket not connected".to_string()))
    }

    fn try_read_varint(data: &[u8]) -> Result<Option<(usize, usize)>> {
        let mut result = 0usize;
        let mut shift = 0usize;

        for (idx, &byte) in data.iter().enumerate().take(SIZE_PACKET_LEN_MAX) {
            result |= ((byte & 0x7F) as usize) << shift;

            if byte & 0x80 == 0 {
                return Ok(Some((result, idx + 1)));
            }

            shift += 7;
        }

        if data.len() >= SIZE_PACKET_LEN_MAX {
            return Err(Error::Other("Invalid varint encoding".to_string()));
        }

        Ok(None)
    }

    fn send_heartbeat_ping(&mut self) -> Result<()> {
        let socket = self.socket_mut()?;
        socket
            .write_all(&[K_HEARTBEAT_PING_TAG, 0])
            .map_err(|e| Error::Other(format!("Failed to send heartbeat ping: {}", e)))?;
        socket
            .flush()
            .map_err(|e| Error::Other(format!("Failed to flush socket: {}", e)))?;
        Ok(())
    }

    pub fn send_login_handshake(&mut self, login_request: &[u8]) -> Result<()> {
        let socket = self.socket_mut()?;
        socket
            .write_all(login_request)
            .map_err(|e| Error::Other(format!("Failed to send login handshake: {}", e)))?;
        socket
            .flush()
            .map_err(|e| Error::Other(format!("Failed to flush socket: {}", e)))?;
        Ok(())
    }

    pub fn close(&mut self) {
        if let Some(mut socket) = self.socket.take() {
            let _ = socket.shutdown();
        }
        self.init();
    }

    pub fn set_on_message<F>(&mut self, callback: F)
    where
        F: Fn(u8, Vec<u8>) -> Result<()> + Send + Sync + 'static,
    {
        self.on_message = Some(Arc::new(callback));
    }

    pub fn set_heartbeat_interval(&mut self, interval: Duration) {
        self.heartbeat_interval = interval;
    }

    fn init(&mut self) {
        self.buffer.clear();
        self.state = MCS_VERSION_TAG_AND_SIZE;
        self.message_tag = 0;
        self.message_size = 0;
        self.last_heartbeat = Instant::now();
    }
}

impl Drop for SocketHandler {
    fn drop(&mut self) {
        self.close();
    }
}
