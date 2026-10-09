use std::{fs::read_to_string, io, path::Path};

use ed25519_dalek::{
    SigningKey, VerifyingKey,
    pkcs8::{DecodePrivateKey as _, DecodePublicKey as _},
};
use httpsig_hyper::prelude::{AlgorithmName, SecretKey};
use ssh_key::{PrivateKey, PublicKey};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum KeyError {
    #[error(transparent)]
    IOError(#[from] io::Error),
    #[error(transparent)]
    HttpSigError(#[from] httpsig_hyper::prelude::HttpSigError),
    #[error(transparent)]
    SSHKeyError(#[from] ssh_key::Error),
    #[error(transparent)]
    ED25519Error(#[from] ed25519_dalek::SignatureError),
    #[error("Key is not of type ED25591")]
    NotED25519,
    #[error("All key extractors failed. Supported types are ED25519 in OpenSSH and PKCS#8 PEM")]
    KeyNotSupported,
}

/// Get a verifying key from either
/// - a public ssh key
/// - a private ssh key (derive)
/// - a public pkcs8 pem file
/// - a private pkcs8 pem file (derive)
/// # Errors
/// will throw an `KeyNotSupported` if it could not find a way to get the key material
pub fn get_verify_key<P: AsRef<Path>>(path: P) -> Result<VerifyingKey, KeyError> {
    let key = read_to_string(path)?;
    verifying_from_private_ssh(&key)
        .or_else(|_| verifying_from_pub_ssh(key.as_str()))
        .or_else(|_| SigningKey::from_pkcs8_pem(key.as_str()).map(|key| key.verifying_key()))
        .or_else(|_| VerifyingKey::from_public_key_pem(key.as_str()))
        .map_err(|_err| KeyError::KeyNotSupported)
}

/// Get a verifying key from either
/// - a private ssh key
/// - a private pkcs8 pem
/// # Errors
/// will throw an `KeyNotSupported` if it could not find a way to get the key material
pub fn get_secret_key<P: AsRef<Path>>(path: P) -> Result<SecretKey, KeyError> {
    let secret_key = read_to_string(path)?;
    secret_from_private_ssh(&secret_key)
        .or_else(|_| SecretKey::from_pem(&AlgorithmName::Ed25519, secret_key.as_str()))
        .map_err(|_err| KeyError::KeyNotSupported)
}

// private key from private ssh key
fn secret_from_private_ssh(key: impl AsRef<[u8]>) -> Result<SecretKey, KeyError> {
    Ok(SecretKey::from_bytes(
        &AlgorithmName::Ed25519,
        &private_ssh_bytes(key)?,
    )?)
}

// public key from private ssh key
fn verifying_from_private_ssh(key: impl AsRef<[u8]>) -> Result<VerifyingKey, KeyError> {
    Ok(SigningKey::from_bytes(&private_ssh_bytes(key)?).verifying_key())
}

// public key from public ssh key
fn verifying_from_pub_ssh(key: &str) -> Result<VerifyingKey, KeyError> {
    Ok(VerifyingKey::from_bytes(&public_ssh_bytes(key)?)?)
}

// ed25519 bytes from private ssh key
fn private_ssh_bytes(key: impl AsRef<[u8]>) -> Result<[u8; 32], KeyError> {
    let key = PrivateKey::from_openssh(key)?;
    Ok(key
        .key_data()
        .ed25519()
        .ok_or(KeyError::NotED25519)?
        .private
        .to_bytes())
}

// ed25519 bytes from pub ssh key
fn public_ssh_bytes(key: &str) -> Result<[u8; 32], KeyError> {
    let key = PublicKey::from_openssh(key)?;
    Ok(key.key_data().ed25519().ok_or(KeyError::NotED25519)?.0)
}
