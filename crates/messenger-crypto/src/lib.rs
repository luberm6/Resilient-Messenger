#![forbid(unsafe_code)]
//! OpenMLS-backed E2EE boundary. No custom ratchet or cryptographic primitive lives here.

use ::tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use messenger_identity::{
    DeviceCertificate, account_id_from_root_public, device_certificate_fingerprint,
    verify_device_certificate,
};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{OpenMlsProvider, types::SignatureScheme};
use rand_core::{OsRng, RngCore};
use std::collections::HashMap;
use thiserror::Error;
use zeroize::Zeroizing;

pub const CIPHERSUITE: Ciphersuite =
    Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;
const STATE_AAD: &[u8] = b"resilient/openmls-state/v1";

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("OpenMLS operation failed: {0}")]
    OpenMls(&'static str),
    #[error("invalid or unauthenticated MLS data")]
    InvalidMessage,
    #[error("conversation was not found")]
    ConversationNotFound,
    #[error("member credential is invalid")]
    InvalidCredential,
    #[error("encrypted state could not be authenticated")]
    StateAuthentication,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemberCredential {
    pub device_id: [u8; 16],
    pub account_id: [u8; 32],
    pub certificate_fingerprint: [u8; 16],
}

impl MemberCredential {
    fn encode(&self) -> Vec<u8> {
        let mut value = Vec::with_capacity(65);
        value.push(1);
        value.extend_from_slice(&self.device_id);
        value.extend_from_slice(&self.account_id);
        value.extend_from_slice(&self.certificate_fingerprint);
        value
    }

    pub fn decode(value: &[u8]) -> Result<Self, CryptoError> {
        if value.len() != 65 || value[0] != 1 {
            return Err(CryptoError::InvalidCredential);
        }
        Ok(Self {
            device_id: value[1..17]
                .try_into()
                .map_err(|_| CryptoError::InvalidCredential)?,
            account_id: value[17..49]
                .try_into()
                .map_err(|_| CryptoError::InvalidCredential)?,
            certificate_fingerprint: value[49..65]
                .try_into()
                .map_err(|_| CryptoError::InvalidCredential)?,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupChange {
    pub commit: Vec<u8>,
    pub welcome: Option<Vec<u8>>,
}

#[derive(Debug, Eq, PartialEq)]
pub enum IncomingMessage {
    Application(Vec<u8>),
    CommitApplied,
    ProposalQueued,
}

/// Each instance represents one MLS device/member and owns an isolated OpenMLS provider.
pub struct CryptoEngine {
    provider: OpenMlsRustCrypto,
    signer: SignatureKeyPair,
    credential: CredentialWithKey,
    groups: HashMap<Vec<u8>, MlsGroup>,
    state_key: Zeroizing<[u8; 32]>,
}

impl CryptoEngine {
    pub fn initialize_crypto_store(
        member: MemberCredential,
        state_key: [u8; 32],
    ) -> Result<Self, CryptoError> {
        let provider = OpenMlsRustCrypto::default();
        let signer = SignatureKeyPair::new(SignatureScheme::ED25519)
            .map_err(|_| CryptoError::OpenMls("signature key generation"))?;
        signer
            .store(provider.storage())
            .map_err(|_| CryptoError::OpenMls("signature key storage"))?;
        let credential = CredentialWithKey {
            credential: BasicCredential::new(member.encode()).into(),
            signature_key: signer.to_public_vec().into(),
        };
        Ok(Self {
            provider,
            signer,
            credential,
            groups: HashMap::new(),
            state_key: Zeroizing::new(state_key),
        })
    }

    pub fn generate_key_packages(&self, count: usize) -> Result<Vec<Vec<u8>>, CryptoError> {
        (0..count.min(100))
            .map(|_| {
                let bundle = KeyPackage::builder()
                    .build(
                        CIPHERSUITE,
                        &self.provider,
                        &self.signer,
                        self.credential.clone(),
                    )
                    .map_err(|_| CryptoError::OpenMls("key package generation"))?;
                bundle
                    .key_package()
                    .tls_serialize_detached()
                    .map_err(|_| CryptoError::OpenMls("key package serialization"))
            })
            .collect()
    }

    pub fn export_public_key_packages(&self, count: usize) -> Result<Vec<Vec<u8>>, CryptoError> {
        self.generate_key_packages(count)
    }

    pub fn create_conversation(&mut self, group_id: &[u8]) -> Result<(), CryptoError> {
        if group_id.is_empty() || group_id.len() > 255 {
            return Err(CryptoError::InvalidMessage);
        }
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(CIPHERSUITE)
            .use_ratchet_tree_extension(true)
            .sender_ratchet_configuration(SenderRatchetConfiguration::new(100, 1_000))
            .build();
        let group = MlsGroup::new_with_group_id(
            &self.provider,
            &self.signer,
            &config,
            GroupId::from_slice(group_id),
            self.credential.clone(),
        )
        .map_err(|_| CryptoError::OpenMls("group creation"))?;
        self.groups.insert(group_id.to_vec(), group);
        Ok(())
    }

    pub fn join_conversation_from_welcome(
        &mut self,
        welcome: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let message = MlsMessageIn::tls_deserialize_exact(welcome)
            .map_err(|_| CryptoError::InvalidMessage)?;
        let welcome = match message.extract() {
            MlsMessageBodyIn::Welcome(welcome) => welcome,
            _ => return Err(CryptoError::InvalidMessage),
        };
        let config = MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .sender_ratchet_configuration(SenderRatchetConfiguration::new(100, 1_000))
            .build();
        let group = StagedWelcome::new_from_welcome(&self.provider, &config, welcome, None)
            .map_err(|_| CryptoError::InvalidMessage)?
            .into_group(&self.provider)
            .map_err(|_| CryptoError::InvalidMessage)?;
        let id = group.group_id().as_slice().to_vec();
        self.groups.insert(id.clone(), group);
        Ok(id)
    }

    pub fn commit_add_members(
        &mut self,
        group_id: &[u8],
        key_packages: &[Vec<u8>],
    ) -> Result<GroupChange, CryptoError> {
        let packages = key_packages
            .iter()
            .map(|bytes| {
                KeyPackageIn::tls_deserialize_exact(bytes)
                    .map_err(|_| CryptoError::InvalidMessage)?
                    .validate(self.provider.crypto(), ProtocolVersion::Mls10)
                    .map_err(|_| CryptoError::InvalidMessage)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let provider = &self.provider;
        let signer = &self.signer;
        let group = self
            .groups
            .get_mut(group_id)
            .ok_or(CryptoError::ConversationNotFound)?;
        let (commit, welcome, _) = group
            .add_members(provider, signer, &packages)
            .map_err(|_| CryptoError::OpenMls("add member commit"))?;
        group
            .merge_pending_commit(provider)
            .map_err(|_| CryptoError::OpenMls("merge add commit"))?;
        Ok(GroupChange {
            commit: commit
                .tls_serialize_detached()
                .map_err(|_| CryptoError::OpenMls("commit serialization"))?,
            welcome: Some(
                welcome
                    .tls_serialize_detached()
                    .map_err(|_| CryptoError::OpenMls("welcome serialization"))?,
            ),
        })
    }

    pub fn propose_add_members(
        &mut self,
        group_id: &[u8],
        key_package: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let package = KeyPackageIn::tls_deserialize_exact(key_package)
            .map_err(|_| CryptoError::InvalidMessage)?
            .validate(self.provider.crypto(), ProtocolVersion::Mls10)
            .map_err(|_| CryptoError::InvalidMessage)?;
        let provider = &self.provider;
        let signer = &self.signer;
        let group = self
            .groups
            .get_mut(group_id)
            .ok_or(CryptoError::ConversationNotFound)?;
        let (proposal, _) = group
            .propose_add_member(provider, signer, &package)
            .map_err(|_| CryptoError::OpenMls("add proposal"))?;
        proposal
            .tls_serialize_detached()
            .map_err(|_| CryptoError::OpenMls("proposal serialization"))
    }

    pub fn commit_remove_members(
        &mut self,
        group_id: &[u8],
        member: &MemberCredential,
    ) -> Result<GroupChange, CryptoError> {
        let wanted = member.encode();
        let provider = &self.provider;
        let signer = &self.signer;
        let group = self
            .groups
            .get_mut(group_id)
            .ok_or(CryptoError::ConversationNotFound)?;
        let index = group
            .members()
            .find(|candidate| candidate.credential.serialized_content() == wanted)
            .map(|candidate| candidate.index)
            .ok_or(CryptoError::InvalidCredential)?;
        let (commit, welcome, _) = group
            .remove_members(provider, signer, &[index])
            .map_err(|_| CryptoError::OpenMls("remove member commit"))?;
        group
            .merge_pending_commit(provider)
            .map_err(|_| CryptoError::OpenMls("merge remove commit"))?;
        Ok(GroupChange {
            commit: commit
                .tls_serialize_detached()
                .map_err(|_| CryptoError::OpenMls("commit serialization"))?,
            welcome: welcome
                .map(|value| value.tls_serialize_detached())
                .transpose()
                .map_err(|_| CryptoError::OpenMls("welcome serialization"))?,
        })
    }

    pub fn propose_remove_members(
        &mut self,
        group_id: &[u8],
        member: &MemberCredential,
    ) -> Result<Vec<u8>, CryptoError> {
        let wanted = member.encode();
        let provider = &self.provider;
        let signer = &self.signer;
        let group = self
            .groups
            .get_mut(group_id)
            .ok_or(CryptoError::ConversationNotFound)?;
        let index = group
            .members()
            .find(|candidate| candidate.credential.serialized_content() == wanted)
            .map(|candidate| candidate.index)
            .ok_or(CryptoError::InvalidCredential)?;
        let (proposal, _) = group
            .propose_remove_member(provider, signer, index)
            .map_err(|_| CryptoError::OpenMls("remove proposal"))?;
        proposal
            .tls_serialize_detached()
            .map_err(|_| CryptoError::OpenMls("proposal serialization"))
    }

    pub fn encrypt_application_message(
        &mut self,
        group_id: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let provider = &self.provider;
        let signer = &self.signer;
        let group = self
            .groups
            .get_mut(group_id)
            .ok_or(CryptoError::ConversationNotFound)?;
        group
            .create_message(provider, signer, plaintext)
            .map_err(|_| CryptoError::OpenMls("application encryption"))?
            .tls_serialize_detached()
            .map_err(|_| CryptoError::OpenMls("message serialization"))
    }

    pub fn process_incoming_message(
        &mut self,
        group_id: &[u8],
        ciphertext: &[u8],
    ) -> Result<IncomingMessage, CryptoError> {
        let message = MlsMessageIn::tls_deserialize_exact(ciphertext)
            .map_err(|_| CryptoError::InvalidMessage)?;
        let protocol: ProtocolMessage = message
            .try_into_protocol_message()
            .map_err(|_| CryptoError::InvalidMessage)?;
        let provider = &self.provider;
        let group = self
            .groups
            .get_mut(group_id)
            .ok_or(CryptoError::ConversationNotFound)?;
        let processed = group
            .process_message(provider, protocol)
            .map_err(|_| CryptoError::InvalidMessage)?;
        Ok(match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(value) => {
                IncomingMessage::Application(value.into_bytes())
            }
            ProcessedMessageContent::StagedCommitMessage(commit) => {
                group
                    .merge_staged_commit(provider, *commit)
                    .map_err(|_| CryptoError::OpenMls("merge incoming commit"))?;
                IncomingMessage::CommitApplied
            }
            ProcessedMessageContent::ProposalMessage(proposal) => {
                group
                    .store_pending_proposal(provider.storage(), *proposal)
                    .map_err(|_| CryptoError::OpenMls("store proposal"))?;
                IncomingMessage::ProposalQueued
            }
            _ => return Err(CryptoError::InvalidMessage),
        })
    }

    pub fn self_update(&mut self, group_id: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let provider = &self.provider;
        let signer = &self.signer;
        let group = self
            .groups
            .get_mut(group_id)
            .ok_or(CryptoError::ConversationNotFound)?;
        let update = group
            .self_update(provider, signer, LeafNodeParameters::default())
            .map_err(|_| CryptoError::OpenMls("self update"))?
            .into_contents()
            .0;
        group
            .merge_pending_commit(provider)
            .map_err(|_| CryptoError::OpenMls("merge self update"))?;
        update
            .tls_serialize_detached()
            .map_err(|_| CryptoError::OpenMls("self update serialization"))
    }

    pub fn get_conversation_epoch(&self, group_id: &[u8]) -> Result<u64, CryptoError> {
        Ok(self
            .groups
            .get(group_id)
            .ok_or(CryptoError::ConversationNotFound)?
            .epoch()
            .as_u64())
    }
    pub fn member_count(&self, group_id: &[u8]) -> Result<usize, CryptoError> {
        Ok(self
            .groups
            .get(group_id)
            .ok_or(CryptoError::ConversationNotFound)?
            .members()
            .count())
    }

    pub fn verify_member_credential(
        &self,
        value: &[u8],
        root_public_key: &[u8; 32],
        certificate: &DeviceCertificate,
    ) -> Result<MemberCredential, CryptoError> {
        let member = MemberCredential::decode(value)?;
        if member.account_id != account_id_from_root_public(root_public_key)
            || member.device_id != certificate.device_id
            || member.certificate_fingerprint != device_certificate_fingerprint(certificate)
            || !verify_device_certificate(root_public_key, certificate)
        {
            return Err(CryptoError::InvalidCredential);
        }
        Ok(member)
    }

    /// Returns an authenticated encrypted snapshot. Raw OpenMLS state never crosses the API.
    pub fn export_conversation_state(&self, group_id: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if !self.groups.contains_key(group_id) {
            return Err(CryptoError::ConversationNotFound);
        }
        let signer = self
            .signer
            .tls_serialize_detached()
            .map_err(|_| CryptoError::OpenMls("signer serialization"))?;
        let values = self
            .provider
            .storage()
            .values
            .read()
            .map_err(|_| CryptoError::OpenMls("storage lock"))?;
        let mut entries = values.iter().collect::<Vec<_>>();
        entries.sort_by(|a, b| a.0.cmp(b.0));
        let mut plain = Vec::new();
        put_bytes(&mut plain, &signer);
        put_bytes(&mut plain, self.credential.credential.serialized_content());
        put_bytes(&mut plain, group_id);
        put_u32(&mut plain, entries.len() as u32);
        for (key, value) in entries {
            put_bytes(&mut plain, key);
            put_bytes(&mut plain, value);
        }
        encrypt_state(&self.state_key, &plain)
    }

    pub fn import_conversation_state(&mut self, encrypted: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let plain = decrypt_state(&self.state_key, encrypted)?;
        let mut input = plain.as_slice();
        let signer_bytes = take_bytes(&mut input)?;
        let identity = take_bytes(&mut input)?;
        let group_id = take_bytes(&mut input)?.to_vec();
        let count = take_u32(&mut input)? as usize;
        let signer = SignatureKeyPair::tls_deserialize_exact(signer_bytes)
            .map_err(|_| CryptoError::StateAuthentication)?;
        let mut values = HashMap::with_capacity(count);
        for _ in 0..count {
            values.insert(
                take_bytes(&mut input)?.to_vec(),
                take_bytes(&mut input)?.to_vec(),
            );
        }
        if !input.is_empty() {
            return Err(CryptoError::StateAuthentication);
        }
        *self
            .provider
            .storage()
            .values
            .write()
            .map_err(|_| CryptoError::OpenMls("storage lock"))? = values;
        self.signer = signer;
        self.credential = CredentialWithKey {
            credential: BasicCredential::new(identity.to_vec()).into(),
            signature_key: self.signer.to_public_vec().into(),
        };
        let group = MlsGroup::load(self.provider.storage(), &GroupId::from_slice(&group_id))
            .map_err(|_| CryptoError::StateAuthentication)?
            .ok_or(CryptoError::StateAuthentication)?;
        self.groups.insert(group_id.clone(), group);
        Ok(group_id)
    }

    pub fn destroy_local_conversation_state(&mut self, group_id: &[u8]) -> Result<(), CryptoError> {
        let mut group = self
            .groups
            .remove(group_id)
            .ok_or(CryptoError::ConversationNotFound)?;
        group
            .delete(self.provider.storage())
            .map_err(|_| CryptoError::OpenMls("group deletion"))
    }
}

fn encrypt_state(key: &[u8; 32], plain: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let mut nonce = [0; 24];
    OsRng.fill_bytes(&mut nonce);
    let mut out = nonce.to_vec();
    out.extend(
        XChaCha20Poly1305::new_from_slice(key)
            .map_err(|_| CryptoError::StateAuthentication)?
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plain,
                    aad: STATE_AAD,
                },
            )
            .map_err(|_| CryptoError::StateAuthentication)?,
    );
    Ok(out)
}
fn decrypt_state(key: &[u8; 32], blob: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if blob.len() < 40 {
        return Err(CryptoError::StateAuthentication);
    }
    Ok(Zeroizing::new(
        XChaCha20Poly1305::new_from_slice(key)
            .map_err(|_| CryptoError::StateAuthentication)?
            .decrypt(
                XNonce::from_slice(&blob[..24]),
                Payload {
                    msg: &blob[24..],
                    aad: STATE_AAD,
                },
            )
            .map_err(|_| CryptoError::StateAuthentication)?,
    ))
}
fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}
fn put_bytes(out: &mut Vec<u8>, value: &[u8]) {
    put_u32(out, value.len() as u32);
    out.extend_from_slice(value);
}
fn take_u32(input: &mut &[u8]) -> Result<u32, CryptoError> {
    if input.len() < 4 {
        return Err(CryptoError::StateAuthentication);
    }
    let value = u32::from_be_bytes(
        input[..4]
            .try_into()
            .map_err(|_| CryptoError::StateAuthentication)?,
    );
    *input = &input[4..];
    Ok(value)
}
fn take_bytes<'a>(input: &mut &'a [u8]) -> Result<&'a [u8], CryptoError> {
    let len = take_u32(input)? as usize;
    if input.len() < len {
        return Err(CryptoError::StateAuthentication);
    }
    let (value, rest) = input.split_at(len);
    *input = rest;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn member(seed: u8) -> MemberCredential {
        MemberCredential {
            device_id: [seed; 16],
            account_id: [seed; 32],
            certificate_fingerprint: [seed; 16],
        }
    }
    #[test]
    fn credential_requires_a_valid_root_signed_device_certificate() {
        let (root, _, certificate) = messenger_identity::create_account();
        let member = MemberCredential {
            device_id: certificate.device_id,
            account_id: messenger_identity::account_id(&root),
            certificate_fingerprint: messenger_identity::device_certificate_fingerprint(
                &certificate,
            ),
        };
        let engine = CryptoEngine::initialize_crypto_store(member.clone(), [3; 32]).unwrap();
        assert_eq!(
            engine
                .verify_member_credential(
                    &member.encode(),
                    &root.0.verifying_key().to_bytes(),
                    &certificate,
                )
                .unwrap(),
            member
        );
        let mut tampered = certificate;
        tampered.signature[0] ^= 1;
        assert!(
            engine
                .verify_member_credential(
                    &member.encode(),
                    &root.0.verifying_key().to_bytes(),
                    &tampered,
                )
                .is_err()
        );
    }

    #[test]
    fn alice_and_bob_exchange_real_mls_messages_and_reject_replay() {
        let mut alice = CryptoEngine::initialize_crypto_store(member(1), [8; 32]).unwrap();
        let mut bob = CryptoEngine::initialize_crypto_store(member(2), [9; 32]).unwrap();
        let bob_package = bob.generate_key_packages(1).unwrap().remove(0);
        alice.create_conversation(b"alice-bob").unwrap();
        let change = alice
            .commit_add_members(b"alice-bob", &[bob_package])
            .unwrap();
        bob.join_conversation_from_welcome(change.welcome.as_ref().unwrap())
            .unwrap();
        let ciphertext = alice
            .encrypt_application_message(b"alice-bob", b"private hello")
            .unwrap();
        assert_eq!(
            bob.process_incoming_message(b"alice-bob", &ciphertext)
                .unwrap(),
            IncomingMessage::Application(b"private hello".to_vec())
        );
        assert!(
            bob.process_incoming_message(b"alice-bob", &ciphertext)
                .is_err()
        );
        let reply = bob
            .encrypt_application_message(b"alice-bob", b"reply")
            .unwrap();
        assert_eq!(
            alice
                .process_incoming_message(b"alice-bob", &reply)
                .unwrap(),
            IncomingMessage::Application(b"reply".to_vec())
        );
    }

    #[test]
    fn encrypted_state_survives_restart_and_wrong_key_fails() {
        let mut first = CryptoEngine::initialize_crypto_store(member(3), [7; 32]).unwrap();
        first.create_conversation(b"persistent").unwrap();
        let snapshot = first.export_conversation_state(b"persistent").unwrap();
        assert!(!snapshot.windows(10).any(|window| window == b"persistent"));
        let mut restored = CryptoEngine::initialize_crypto_store(member(3), [7; 32]).unwrap();
        assert_eq!(
            restored.import_conversation_state(&snapshot).unwrap(),
            b"persistent"
        );
        assert_eq!(restored.get_conversation_epoch(b"persistent").unwrap(), 0);
        let mut wrong = CryptoEngine::initialize_crypto_store(member(3), [6; 32]).unwrap();
        assert!(wrong.import_conversation_state(&snapshot).is_err());
    }
    #[test]
    fn ten_and_hundred_member_groups_are_real_openmls_groups() {
        for count in [10_usize, 100] {
            let mut owner = CryptoEngine::initialize_crypto_store(member(1), [5; 32]).unwrap();
            let group_id = format!("group-{count}");
            owner.create_conversation(group_id.as_bytes()).unwrap();
            let mut packages = Vec::new();
            for index in 1..count {
                let participant = CryptoEngine::initialize_crypto_store(
                    member((index % 250) as u8 + 2),
                    [index as u8; 32],
                )
                .unwrap();
                packages.push(participant.generate_key_packages(1).unwrap().remove(0));
            }
            let change = owner
                .commit_add_members(group_id.as_bytes(), &packages)
                .unwrap();
            assert!(change.welcome.is_some());
            assert_eq!(owner.member_count(group_id.as_bytes()).unwrap(), count);
            let ciphertext = owner
                .encrypt_application_message(group_id.as_bytes(), b"group message")
                .unwrap();
            assert!(!ciphertext.is_empty());
        }
    }

    #[test]
    fn out_of_order_and_removed_member_rules_hold() {
        let mut alice = CryptoEngine::initialize_crypto_store(member(10), [1; 32]).unwrap();
        let mut bob = CryptoEngine::initialize_crypto_store(member(11), [2; 32]).unwrap();
        let bob_package = bob.generate_key_packages(1).unwrap().remove(0);
        alice.create_conversation(b"ordering").unwrap();
        let welcome = alice
            .commit_add_members(b"ordering", &[bob_package])
            .unwrap()
            .welcome
            .unwrap();
        bob.join_conversation_from_welcome(&welcome).unwrap();
        let first = alice
            .encrypt_application_message(b"ordering", b"first")
            .unwrap();
        let second = alice
            .encrypt_application_message(b"ordering", b"second")
            .unwrap();
        assert_eq!(
            bob.process_incoming_message(b"ordering", &second).unwrap(),
            IncomingMessage::Application(b"second".to_vec())
        );
        assert_eq!(
            bob.process_incoming_message(b"ordering", &first).unwrap(),
            IncomingMessage::Application(b"first".to_vec())
        );
        let removal = alice
            .commit_remove_members(b"ordering", &member(11))
            .unwrap();
        assert_eq!(
            bob.process_incoming_message(b"ordering", &removal.commit)
                .unwrap(),
            IncomingMessage::CommitApplied
        );
        let after = alice
            .encrypt_application_message(b"ordering", b"after removal")
            .unwrap();
        assert!(bob.process_incoming_message(b"ordering", &after).is_err());
    }

    #[test]
    fn delayed_welcome_works_and_simultaneous_commits_are_detected() {
        let mut alice = CryptoEngine::initialize_crypto_store(member(20), [20; 32]).unwrap();
        let mut bob = CryptoEngine::initialize_crypto_store(member(21), [21; 32]).unwrap();
        let bob_package = bob.generate_key_packages(1).unwrap().remove(0);
        alice.create_conversation(b"delayed-welcome").unwrap();
        let change = alice
            .commit_add_members(b"delayed-welcome", &[bob_package])
            .unwrap();
        let queued_while_offline = alice
            .encrypt_application_message(b"delayed-welcome", b"after welcome was queued")
            .unwrap();
        bob.join_conversation_from_welcome(change.welcome.as_ref().unwrap())
            .unwrap();
        assert_eq!(
            bob.process_incoming_message(b"delayed-welcome", &queued_while_offline)
                .unwrap(),
            IncomingMessage::Application(b"after welcome was queued".to_vec())
        );

        let alice_commit = alice.self_update(b"delayed-welcome").unwrap();
        let bob_commit = bob.self_update(b"delayed-welcome").unwrap();
        // Both commits were created from the same epoch. Neither engine silently
        // accepts the competing branch after merging its own; sync must reconcile.
        assert!(
            alice
                .process_incoming_message(b"delayed-welcome", &bob_commit)
                .is_err()
        );
        assert!(
            bob.process_incoming_message(b"delayed-welcome", &alice_commit)
                .is_err()
        );
        assert_eq!(
            alice.get_conversation_epoch(b"delayed-welcome").unwrap(),
            bob.get_conversation_epoch(b"delayed-welcome").unwrap()
        );
    }
}
