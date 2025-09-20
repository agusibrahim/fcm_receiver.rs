# Rust FCM Receiver

<a href="https://crates.io/crates/fcm_receiver_rs"><img alt="fcm_receiver_rs on crates.io" src="https://img.shields.io/crates/v/fcm_receiver_rs"/></a>

A Rust library that simulates an Android device to receive Firebase Cloud Messaging (FCM) notifications. This library allows your application to behave like a real device when receiving push notifications from FCM servers.

## Overview

This library emulates Android device functionality in the FCM ecosystem, including the ability to:
- Register as a new device and obtain FCM/GCM tokens
- Receive push notifications in real-time
- Subscribe to and unsubscribe from specific topics
- Handle encrypted messages properly

The FCM/GCM tokens generated can be used to send notifications to this simulated device, just like sending notifications to a real Android device.

## Features

- **Device Emulation**: Behaves like a real Android device in the FCM ecosystem
- **Token Generation**: Generates valid FCM and GCM tokens for receiving notifications
- **Topic Management**: Subscribe and unsubscribe from FCM topics like a regular device
- **Real-time Notifications**: Receive push notifications in real-time through persistent connections

## Manual Protobuf Implementation

**Important**: This library implements FCM protobuf messages manually without using the `protobuf` library. While FCM communication uses protobuf over socket connections, this library:

- Manually encodes and decodes protobuf messages
- Does not require protobuf compilation or reflection
- Implements only the necessary FCM message types
- Provides a lightweight alternative to full protobuf dependencies

This approach keeps the library lightweight and avoids the complexity of protobuf compilation while maintaining full compatibility with FCM protocols.

## Technical Documentation

For detailed technical information about the FCM protocol implementation, see [TECHNICAL.md](TECHNICAL.md).

The TECHNICAL.md document provides:
- End-to-end explanation of building an FCM receiver from scratch
- Detailed protocol flow including device check-in, registration, and MCS connection
- Complete request/response examples for all FCM endpoints
- Manual protobuf implementation details without external dependencies
- Topic subscription/unsubscription implementation based on microg/GmsCore
- Error handling strategies and implementation checklist

This technical guide is essential for understanding how the library works internally and can help with debugging or extending the functionality.

## Android Package Configuration (optional)

For Firebase projects with protection/restrictions, you need to properly configure the Android package information. This is crucial when Firebase is configured to only accept connections from specific Android packages.

### Package ID and Signature Configuration

```rust
use fcm_receiver_rs::client::{FcmClient, AndroidApp};

fn main() -> Result<()> {
    let mut client = FcmClient::new(
        "YOUR_API_KEY".to_string(),
        "YOUR_APP_ID".to_string(),
        "YOUR_PROJECT_ID".to_string(),
    )?;

    // Configure Android package information
    client.android_app = Some(AndroidApp {
        gcm_sender_id: "123456789".to_string(),  // Your sender id
        android_package: "com.example.app".to_string(),  // Your Android package name
        android_package_cert: "YOUR_SHA1_SIGNATURE".to_string(),  // SHA1 signature of your APK
    });

    // Continue with registration...
    Ok(())
}
```

### Generating SHA1 Signature

For testing purposes, you can use a SHA1 signature from a real APK or generate one:

```bash
# Get SHA1 from debug keystore (for development)
keytool -list -v -keystore ~/.android/debug.keystore -alias androiddebugkey -storepass android -keypass android

# Or use a known SHA1 from a production app
# Example: "2E:4A:3B:8C:1D:9E:F5:A0:B6:C7:D8:E9:F0:A1:B2:C3:D4:E5:F6"
# Just passing: "2E4A3B8C1D9EF5A0B6C7D8E9F0A1B2C3D4E5F6"
```

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
fcm_receiver_rs = { path = "./fcm_receiver_rs" }
```

## Quick Start

```rust
use fcm_receiver_rs::client::FcmClient;
use fcm_receiver_rs::Result;
use std::sync::Arc;

fn main() -> Result<()> {
    // Initialize FCM client
    let mut client = FcmClient::new(
        "YOUR_API_KEY".to_string(),
        "YOUR_APP_ID".to_string(),
        "YOUR_PROJECT_ID".to_string(),
    )?;

    // Configure Android package for Firebase compatibility (optional)
    client.android_app = Some(fcm_receiver_rs::client::AndroidApp {
        gcm_sender_id: "123456789".to_string(),
        android_package: "com.example.app".to_string(),
        android_package_cert: "YOUR_SHA1_SIGNATURE".to_string(),
    });

    // Set up notification handler
    client.on_data_message = Some(Arc::new(|payload| {
        let text = String::from_utf8_lossy(&payload);
        println!("Received notification: {}", text);
    }));

    // Generate encryption keys
    let (private_key_b64, auth_secret_b64) = client.create_new_keys()?;
    client.load_keys(&private_key_b64, &auth_secret_b64)?;

    // Register as device and get tokens
    let (fcm_token, gcm_token, android_id, security_token) = client.register()?;
    println!("Registration successful!");
    println!("FCM Token: {}", fcm_token);
    println!("GCM Token: {}", gcm_token);
    println!("Android ID: {}", android_id);

    // Save tokens for server use
    // These tokens can be used in FCM HTTP API v1

    // Subscribe to topic
    client.subscribe_to_topic("promotions")?;

    // Start listening for notifications
    client.start_listening()?;

    Ok(())
}
```

## Usage

### 1. Getting FCM/GCM Tokens

The generated tokens can be used by servers to send notifications:

```rust
// Register device
let (fcm_token, gcm_token, android_id, security_token) = client.register()?;

// FCM Token can be used in FCM HTTP API v1
// Format: fcm_token can be used directly in FCM endpoints
println!("FCM Token for server: {}", fcm_token);
```

### 2. Managing Topics

Subscribe and unsubscribe from topics like a real Android device:

```rust
// Subscribe to topics
client.subscribe_to_topic("news")?;
client.subscribe_to_topic("promotions")?;

// Unsubscribe from topics
client.unsubscribe_from_topic("old_topic")?;
```

### 3. Receiving Notifications

After subscribing to topics, the device will receive notifications sent to those topics:

```rust
// Handler for decrypted notifications
client.on_data_message = Some(Arc::new(|payload| {
    let text = String::from_utf8_lossy(&payload);
    println!("Incoming notification: {}", text);
}));

// Handler for raw messages (for debugging)
client.on_raw_message = Some(Arc::new(|msg| {
    println!("Raw message: {:?}", msg);
}));
```

## Server Integration

The generated FCM tokens can be used on servers to send notifications. Example using curl:

```bash
# Send notification to simulated device
curl -X POST https://fcm.googleapis.com/v1/projects/YOUR_PROJECT_ID/messages:send \
  -H "Authorization: Bearer YOUR_SERVER_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "message": {
      "token": "FCM_TOKEN_FROM_SIMULATED_DEVICE",
      "notification": {
        "title": "Test Notification",
        "body": "Hello from server!"
      },
      "data": {
        "custom_data": "value"
      }
    }
  }'
```

## Project Reference

The topic subscription/unsubscription implementation in this library references the [microg/GmsCore](https://github.com/microg/GmsCore) project, which is an open-source implementation of Google Play Services.

## Complete Example

See the `example/` directory for a complete implementation that includes:
- Save and load device credentials
- Handle different message types
- Topic subscription
- Error handling

Run the example:

```bash
cd example
cargo run
```

## Configuration

### Required Credentials

- **API Key**: FCM server API key
- **App ID**: Firebase app ID (format: `1:123456789:android:abc123`)
- **Project ID**: Firebase project ID

### Optional Configuration

- **Heartbeat Interval**: Heartbeat interval to server (default: 600 seconds)
- **Android App Info**: For Android-specific features and Firebase compatibility

## Security Notes

- Private keys and auth secrets should be stored securely
- Use HTTPS for all network communications
- Validate all incoming messages
- Keep API keys confidential
- Use proper SHA1 signatures when mimicking real apps

## Dependencies

- `reqwest` - HTTP client
- `serde` - JSON serialization
- `p256` - Elliptic curve cryptography
- `aes-gcm` - AES encryption
- `base64` - Base64 encoding/decoding

**Note**: This library does NOT use `protobuf` as a dependency. All protobuf messages are implemented manually.

## License

This project is licensed under the MIT License.
