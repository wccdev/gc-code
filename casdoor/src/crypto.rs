use anyhow::{Context, Result};
use base64::prelude::*;
use rand::rngs::OsRng;
use rand::RngCore;
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::{Oaep, RsaPublicKey};
use sha2::Sha256;

/// Encrypt a string using the RSA public key provided by the Zed desktop client.
///
/// The public key is base64url-encoded PKCS1 DER format.
/// Encryption uses OAEP with SHA-256 (matching Zed's V1 EncryptionFormat).
pub fn encrypt_with_zed_public_key(public_key_b64: &str, plaintext: &str) -> Result<String> {
    let der_bytes = BASE64_URL_SAFE
        .decode(public_key_b64)
        .context("failed to base64-decode public key")?;
    let public_key =
        RsaPublicKey::from_pkcs1_der(&der_bytes).context("failed to parse RSA public key")?;

    let padding = Oaep::new::<Sha256>();
    let encrypted = public_key
        .encrypt(&mut OsRng, padding, plaintext.as_bytes())
        .context("RSA encryption failed")?;

    Ok(BASE64_URL_SAFE.encode(&encrypted))
}

/// Generate a random 64-character base64url token (matching Zed's `random_token`).
pub fn random_token() -> String {
    let mut bytes = [0u8; 48];
    OsRng.fill_bytes(&mut bytes);
    BASE64_URL_SAFE.encode(bytes)
}
