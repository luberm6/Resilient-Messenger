#![forbid(unsafe_code)]
//! Client-owned anonymous identity. Root secrets and recovery phrases never leave this crate.
use bip39::{Language, Mnemonic};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit},
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use unicode_normalization::UnicodeNormalization;
pub const ACCOUNT_ID_DOMAIN: &[u8] = b"resilient/account-id/v1";

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum IdentityError {
    #[error("identity input is invalid")]
    InvalidInput,
    #[error("identity cryptographic operation failed")]
    CryptographicFailure,
}
#[derive(Clone)]
pub struct AccountRoot(pub SigningKey);
#[derive(Clone)]
pub struct DeviceKey(pub SigningKey);
#[derive(Clone, Debug)]
pub struct DeviceCertificate {
    pub device_id: [u8; 16],
    pub device_public_key: [u8; 32],
    pub issued_at: u64,
    pub signature: [u8; 64],
}
#[derive(Clone, Debug)]
pub struct SignedInvite {
    pub version: u8,
    pub account_id: [u8; 32],
    pub fingerprint: [u8; 16],
    pub expires_at: Option<u64>,
    pub signature: [u8; 64],
}
#[derive(Clone, Debug)]
pub struct RecoveryPackage {
    pub phrase: Mnemonic,
    pub recovery_identifier: [u8; 32],
    pub encrypted_root: Vec<u8>,
}
pub fn create_account() -> (AccountRoot, DeviceKey, DeviceCertificate) {
    let root = AccountRoot(SigningKey::generate(&mut OsRng));
    let device = DeviceKey(SigningKey::generate(&mut OsRng));
    let cert = sign_device_certificate(&root, &device);
    (root, device, cert)
}
pub fn account_id(root: &AccountRoot) -> [u8; 32] {
    account_id_from_root_public(root.0.verifying_key().as_bytes())
}
pub fn account_id_from_root_public(root_public: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(ACCOUNT_ID_DOMAIN);
    h.update(root_public);
    h.finalize().into()
}
pub fn sign_device_certificate(root: &AccountRoot, device: &DeviceKey) -> DeviceCertificate {
    let mut id = [0; 16];
    OsRng.fill_bytes(&mut id);
    let issued = now();
    let mut v = Vec::new();
    v.extend_from_slice(&id);
    v.extend_from_slice(device.0.verifying_key().as_bytes());
    v.extend_from_slice(&issued.to_be_bytes());
    let sig = root.0.sign(&v).to_bytes();
    DeviceCertificate {
        device_id: id,
        device_public_key: device.0.verifying_key().to_bytes(),
        issued_at: issued,
        signature: sig,
    }
}
pub fn verify_device_certificate(root_public: &[u8; 32], cert: &DeviceCertificate) -> bool {
    let Ok(root) = VerifyingKey::from_bytes(root_public) else {
        return false;
    };
    let mut v = Vec::new();
    v.extend_from_slice(&cert.device_id);
    v.extend_from_slice(&cert.device_public_key);
    v.extend_from_slice(&cert.issued_at.to_be_bytes());
    root.verify(&v, &Signature::from_bytes(&cert.signature))
        .is_ok()
}

pub fn device_certificate_fingerprint(cert: &DeviceCertificate) -> [u8; 16] {
    let mut digest = Sha256::new();
    digest.update(b"resilient/device-certificate-fingerprint/v1");
    digest.update(device_certificate_signing_payload(cert));
    digest.update(cert.signature);
    let digest = digest.finalize();
    let mut fingerprint = [0; 16];
    fingerprint.copy_from_slice(&digest[..16]);
    fingerprint
}
pub fn device_certificate_signing_payload(cert: &DeviceCertificate) -> Vec<u8> {
    let mut value = Vec::with_capacity(56);
    value.extend_from_slice(&cert.device_id);
    value.extend_from_slice(&cert.device_public_key);
    value.extend_from_slice(&cert.issued_at.to_be_bytes());
    value
}
pub fn auth_challenge_payload(challenge_id: &[u8; 16], challenge: &[u8; 32]) -> Vec<u8> {
    let mut value = b"resilient/auth-challenge/v1".to_vec();
    value.extend_from_slice(challenge_id);
    value.extend_from_slice(challenge);
    value
}
pub fn refresh_proof_payload(refresh_token: &[u8; 32]) -> Vec<u8> {
    let mut value = b"resilient/refresh-proof/v1".to_vec();
    value.extend_from_slice(refresh_token);
    value
}
pub fn generate_recovery_phrase() -> Mnemonic {
    Mnemonic::generate_in(Language::English, 24).expect("supported entropy")
}
pub fn create_recovery_package(root: &AccountRoot) -> Result<RecoveryPackage, IdentityError> {
    let phrase = generate_recovery_phrase();
    let encrypted_root = encrypt_recovery_blob(&phrase, &root.0.to_bytes())?;
    Ok(RecoveryPackage {
        recovery_identifier: recovery_identifier(&phrase),
        phrase,
        encrypted_root,
    })
}
pub fn restore_account_root(
    phrase: &str,
    encrypted_root: &[u8],
) -> Result<AccountRoot, IdentityError> {
    let phrase = Mnemonic::parse_in_normalized(Language::English, phrase)
        .map_err(|_| IdentityError::InvalidInput)?;
    let bytes = decrypt_recovery_blob(&phrase, encrypted_root)?;
    let secret: [u8; 32] = bytes.try_into().map_err(|_| IdentityError::InvalidInput)?;
    Ok(AccountRoot(SigningKey::from_bytes(&secret)))
}
pub fn recovery_identifier(phrase: &Mnemonic) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"resilient/recovery-id/v1");
    h.update(phrase.to_entropy());
    h.finalize().into()
}
pub fn encrypt_recovery_blob(
    phrase: &Mnemonic,
    plaintext: &[u8],
) -> Result<Vec<u8>, IdentityError> {
    let hk = Hkdf::<Sha256>::new(Some(b"resilient/recovery/salt/v1"), &phrase.to_entropy());
    let mut key = [0; 32];
    hk.expand(b"recovery-blob", &mut key)
        .map_err(|_| IdentityError::CryptographicFailure)?;
    let mut nonce = [0; 24];
    OsRng.fill_bytes(&mut nonce);
    let c =
        XChaCha20Poly1305::new_from_slice(&key).map_err(|_| IdentityError::CryptographicFailure)?;
    let mut out = nonce.to_vec();
    out.extend(
        c.encrypt(XNonce::from_slice(&nonce), plaintext)
            .map_err(|_| IdentityError::CryptographicFailure)?,
    );
    Ok(out)
}
pub fn decrypt_recovery_blob(phrase: &Mnemonic, blob: &[u8]) -> Result<Vec<u8>, IdentityError> {
    if blob.len() < 24 {
        return Err(IdentityError::InvalidInput);
    }
    let hk = Hkdf::<Sha256>::new(Some(b"resilient/recovery/salt/v1"), &phrase.to_entropy());
    let mut key = [0; 32];
    hk.expand(b"recovery-blob", &mut key)
        .map_err(|_| IdentityError::CryptographicFailure)?;
    XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|_| IdentityError::CryptographicFailure)?
        .decrypt(XNonce::from_slice(&blob[..24]), &blob[24..])
        .map_err(|_| IdentityError::CryptographicFailure)
}
pub fn canonical_username(input: &str) -> Result<String, IdentityError> {
    let v = input
        .nfkc()
        .flat_map(char::to_lowercase)
        .collect::<String>();
    if !(3..=32).contains(&v.chars().count())
        || v.chars()
            .any(|c| c.is_control() || !(c.is_ascii_alphanumeric() || c == '_' || c == '.'))
    {
        return Err(IdentityError::InvalidInput);
    }
    Ok(v)
}
pub fn sign_invite(root: &AccountRoot, expires_at: Option<u64>) -> SignedInvite {
    let id = account_id(root);
    let mut fp = [0; 16];
    fp.copy_from_slice(&root.0.verifying_key().as_bytes()[..16]);
    let mut v = vec![1];
    v.extend_from_slice(&id);
    v.extend_from_slice(&fp);
    v.extend_from_slice(&expires_at.unwrap_or(0).to_be_bytes());
    let s = root.0.sign(&v).to_bytes();
    SignedInvite {
        version: 1,
        account_id: id,
        fingerprint: fp,
        expires_at,
        signature: s,
    }
}
pub fn verify_invite(root_public: &[u8; 32], invite: &SignedInvite, at: u64) -> bool {
    if invite.version != 1 || invite.expires_at.is_some_and(|x| x < at) {
        return false;
    }
    let Ok(root) = VerifyingKey::from_bytes(root_public) else {
        return false;
    };
    let mut v = vec![invite.version];
    v.extend_from_slice(&invite.account_id);
    v.extend_from_slice(&invite.fingerprint);
    v.extend_from_slice(&invite.expires_at.unwrap_or(0).to_be_bytes());
    root.verify(&v, &Signature::from_bytes(&invite.signature))
        .is_ok()
}
pub fn encode_qr_payload(
    root: &AccountRoot,
    invite: &SignedInvite,
) -> Result<Vec<u8>, IdentityError> {
    let public = root.0.verifying_key().to_bytes();
    if !verify_invite(&public, invite, 0) || account_id(root) != invite.account_id {
        return Err(IdentityError::InvalidInput);
    }
    let mut value = b"RMQ1".to_vec();
    value.extend_from_slice(&public);
    value.push(invite.version);
    value.extend_from_slice(&invite.account_id);
    value.extend_from_slice(&invite.fingerprint);
    value.push(u8::from(invite.expires_at.is_some()));
    value.extend_from_slice(&invite.expires_at.unwrap_or(0).to_be_bytes());
    value.extend_from_slice(&invite.signature);
    Ok(value)
}
pub fn decode_and_verify_qr_payload(
    value: &[u8],
    at: u64,
) -> Result<([u8; 32], SignedInvite), IdentityError> {
    if value.len() != 158 || &value[..4] != b"RMQ1" {
        return Err(IdentityError::InvalidInput);
    }
    let root_public: [u8; 32] = value[4..36]
        .try_into()
        .map_err(|_| IdentityError::InvalidInput)?;
    let has_expiry = value[85];
    if has_expiry > 1 {
        return Err(IdentityError::InvalidInput);
    }
    let expiry = u64::from_be_bytes(
        value[86..94]
            .try_into()
            .map_err(|_| IdentityError::InvalidInput)?,
    );
    let invite = SignedInvite {
        version: value[36],
        account_id: value[37..69]
            .try_into()
            .map_err(|_| IdentityError::InvalidInput)?,
        fingerprint: value[69..85]
            .try_into()
            .map_err(|_| IdentityError::InvalidInput)?,
        expires_at: (has_expiry == 1).then_some(expiry),
        signature: value[94..158]
            .try_into()
            .map_err(|_| IdentityError::InvalidInput)?,
    };
    if verify_invite(&root_public, &invite, at)
        && account_id_from_root_public(&root_public) == invite.account_id
    {
        Ok((root_public, invite))
    } else {
        Err(IdentityError::InvalidInput)
    }
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn identity_and_recovery() {
        let (r, _, c) = create_account();
        assert!(verify_device_certificate(
            &r.0.verifying_key().to_bytes(),
            &c
        ));
        let p = generate_recovery_phrase();
        let x = encrypt_recovery_blob(&p, b"root key backup").unwrap();
        assert_eq!(decrypt_recovery_blob(&p, &x).unwrap(), b"root key backup");
        assert!(canonical_username("Test_Name").is_ok());
        assert_eq!(canonical_username("teSt").unwrap(), "test")
    }
    #[test]
    fn tampering_fails() {
        let (r, _, _) = create_account();
        let mut i = sign_invite(&r, None);
        i.account_id[0] ^= 1;
        assert!(!verify_invite(&r.0.verifying_key().to_bytes(), &i, 0))
    }
    #[test]
    fn recovery_restores_root_but_not_message_history() {
        let (root, _, _) = create_account();
        let id = account_id(&root);
        let package = create_recovery_package(&root).unwrap();
        assert!(
            !package
                .encrypted_root
                .windows(32)
                .any(|window| window == root.0.to_bytes())
        );
        let restored =
            restore_account_root(&package.phrase.to_string(), &package.encrypted_root).unwrap();
        assert_eq!(account_id(&restored), id);
        let mut words = package
            .phrase
            .to_string()
            .split_whitespace()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        words[0] = "abandon".into();
        assert!(restore_account_root(&words.join(" "), &package.encrypted_root).is_err());
        assert!(restore_account_root("one malformed word", &package.encrypted_root).is_err());
    }
    #[test]
    fn qr_round_trip_and_tamper_rejection() {
        let (root, _, _) = create_account();
        let invite = sign_invite(&root, Some(now() + 60));
        let payload = encode_qr_payload(&root, &invite).unwrap();
        assert_eq!(
            decode_and_verify_qr_payload(&payload, now())
                .unwrap()
                .1
                .account_id,
            account_id(&root)
        );
        let mut tampered = payload;
        tampered[70] ^= 1;
        assert!(decode_and_verify_qr_payload(&tampered, now()).is_err());
    }
}
