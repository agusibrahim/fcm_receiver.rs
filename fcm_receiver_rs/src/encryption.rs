use crate::crypto::public_key_bytes;
use crate::error::{Error, Result};
use ece::crypto::EcKeyComponents;
use ece::legacy::{decrypt_aesgcm, AesGcmEncryptedBlock};
use p256::SecretKey;

const DEFAULT_RECORD_SIZE: u32 = 4096;

pub fn decrypt_message(
    crypto_key: &[u8],
    encryption: &[u8],
    raw_data: &[u8],
    auth_secret: &[u8],
    private_key: &SecretKey,
) -> Result<Vec<u8>> {
    if raw_data.is_empty() {
        return Err(Error::InvalidData("raw data payload missing"));
    }

    let block = AesGcmEncryptedBlock::new(
        crypto_key,
        encryption,
        DEFAULT_RECORD_SIZE,
        raw_data.to_vec(),
    )
    .map_err(|err| Error::Other(format!("failed to create encrypted block: {err}")))?;

    let public_key = private_key.public_key();
    let private_bytes = private_key.to_bytes().to_vec();
    let public_bytes = public_key_bytes(&public_key);
    let components = EcKeyComponents::new(private_bytes, public_bytes);

    decrypt_aesgcm(&components, auth_secret, &block)
        .map_err(|err| Error::Other(format!("failed to decrypt message: {err}")))
}
