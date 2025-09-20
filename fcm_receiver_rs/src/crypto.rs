use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes128Gcm, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use p256::ecdh::diffie_hellman;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use p256::{EncodedPoint, PublicKey, SecretKey};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;

use crate::error::{Error, Result};

pub fn create_keys() -> Result<(SecretKey, PublicKey, Vec<u8>)> {
    let private_key = SecretKey::random(&mut OsRng);
    let public_key = private_key.public_key();
    let auth_secret = create_auth_secret()?;
    Ok((private_key, public_key, auth_secret))
}

pub fn create_auth_secret() -> Result<Vec<u8>> {
    let mut secret = vec![0u8; 16];
    OsRng.fill_bytes(&mut secret);
    Ok(secret)
}

pub fn encode_private_key(key: &SecretKey) -> Result<Vec<u8>> {
    let der = key
        .to_pkcs8_der()
        .map_err(|err| Error::Crypto(format!("pkcs8 encode failed: {err}")))?;
    Ok(der.as_bytes().to_vec())
}

pub fn decode_private_key(bytes: &[u8]) -> Result<SecretKey> {
    let key = SecretKey::from_pkcs8_der(bytes)
        .map_err(|err| Error::Crypto(format!("pkcs8 decode failed: {err}")))?;
    Ok(key)
}

pub fn public_key_bytes(key: &PublicKey) -> Vec<u8> {
    key.to_encoded_point(false).as_bytes().to_vec()
}

pub fn decrypt_message(
    crypto_key: &[u8],
    encryption_salt: &[u8],
    raw_data: &[u8],
    auth_secret: &[u8],
    private_key: &SecretKey,
    public_key: &PublicKey,
) -> Result<Vec<u8>> {
    let remote_point = EncodedPoint::from_bytes(crypto_key)
        .map_err(|_| Error::InvalidData("invalid dh public key"))?;
    let remote_public = PublicKey::from_sec1_bytes(remote_point.as_bytes())
        .map_err(|_| Error::InvalidData("invalid dh public key"))?;

    let shared_secret = diffie_hellman(private_key.to_nonzero_scalar(), remote_public.as_affine());
    let shared_bytes = shared_secret.raw_secret_bytes();

    let prk_key = hkdf_extract(auth_secret, shared_bytes.as_slice())?;

    let hkdf_salt = Hkdf::<Sha256>::new(Some(encryption_salt), prk_key.as_slice());

    let client_public = public_key_bytes(public_key);
    let server_public = remote_public.to_encoded_point(false).as_bytes().to_vec();

    let context = build_context(&client_public, &server_public);
    let mut cek_info = Vec::with_capacity(24 + context.len());
    cek_info.extend_from_slice(b"Content-Encoding: aesgcm");
    cek_info.push(0);
    cek_info.extend_from_slice(&context);

    let mut nonce_info = Vec::with_capacity(24 + context.len());
    nonce_info.extend_from_slice(b"Content-Encoding: nonce");
    nonce_info.push(0);
    nonce_info.extend_from_slice(&context);

    let mut cek = [0u8; 16];
    hkdf_salt
        .expand(&cek_info, &mut cek)
        .map_err(|_| Error::Crypto("hkdf expand cek failed".into()))?;

    let mut nonce_bytes = [0u8; 12];
    hkdf_salt
        .expand(&nonce_info, &mut nonce_bytes)
        .map_err(|_| Error::Crypto("hkdf expand nonce failed".into()))?;

    let cipher = Aes128Gcm::new_from_slice(&cek)
        .map_err(|_| Error::Crypto("failed to init AES key".into()))?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, raw_data)
        .map_err(|_| Error::Crypto("failed to decrypt message".into()))?;

    Ok(plaintext)
}

fn build_context(client_public: &[u8], server_public: &[u8]) -> Vec<u8> {
    let mut context = Vec::with_capacity(1 + 2 + client_public.len() + 2 + server_public.len());
    context.push(0);
    context.extend_from_slice(&(client_public.len() as u16).to_be_bytes());
    context.extend_from_slice(client_public);
    context.extend_from_slice(&(server_public.len() as u16).to_be_bytes());
    context.extend_from_slice(server_public);
    context
}

fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> Result<[u8; 32]> {
    let key_material = if salt.is_empty() {
        vec![0u8; 32]
    } else {
        salt.to_vec()
    };

    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&key_material)
        .map_err(|_| Error::Crypto("invalid hmac key".into()))?;
    mac.update(ikm);
    let result = mac.finalize().into_bytes();
    let mut prk = [0u8; 32];
    prk.copy_from_slice(&result);
    Ok(prk)
}
