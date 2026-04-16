use anyhow::{anyhow, Result};
use blake3::Hasher;
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    Key, XChaCha20Poly1305, XNonce,
};
use distributed_topic_tracker::TopicId;
use hkdf::Hkdf;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use spake2::{Ed25519Group, Identity, Password, Spake2};
use zeroize::Zeroizing;

use super::phrase_proto::{ReceiverHello, SenderOffer, PHRASE_PROTOCOL_VERSION};

const DOMAIN_TOPIC: &[u8] = b"sendme/phrase/topic/v1";
const DOMAIN_SHARE: &[u8] = b"sendme/phrase/share-id/v1";
const DOMAIN_SENDER_COMMITMENT: &[u8] = b"sendme/phrase/sender-commit/v1";
const DOMAIN_RECEIVER_COMMITMENT: &[u8] = b"sendme/phrase/receiver-commit/v1";
const DOMAIN_KDF: &[u8] = b"sendme/phrase/session-key/v1";
const DOMAIN_ACK: &[u8] = b"sendme/phrase/ack/v1";
const ID_A: &[u8] = b"sendme-phrase-sender";
const ID_B: &[u8] = b"sendme-phrase-receiver";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TicketEnvelope {
    pub ticket: String,
    pub ticket_hash: String,
    pub issued_at_ms: u64,
}

pub struct SenderPakeState {
    pub state: Spake2<Ed25519Group>,
    pub offer: SenderOffer,
}

pub struct ReceiverPakeState {
    pub state: Spake2<Ed25519Group>,
    pub hello: ReceiverHello,
}

/// # Description
/// Derives a topic ID from a phrase.
/// The topic ID is derived by hashing the phrase with blake3, and then encoding the hash as a hex string.
pub fn derive_topic_id(phrase: &str) -> TopicId {
    let mut h = Hasher::new();
    h.update(DOMAIN_TOPIC);
    h.update(phrase.as_bytes());
    TopicId::new(h.finalize().to_hex().to_string())
}

/// Derives a share ID from a ticket.
/// The share ID is derived by hashing the ticket with blake3, and then taking the first 32 bytes of the hash.
pub fn derive_share_id(ticket: &str) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(DOMAIN_SHARE);
    h.update(ticket.as_bytes());
    *h.finalize().as_bytes()
}

/// Generates a sender offer for a given phrase and share ID.
pub fn new_sender_offer(
    phrase: &str,
    share_id: [u8; 32],
    now_ms: u64,
    expires_at_ms: u64,
) -> SenderPakeState {
    // derive the PAKE state and first message
    let password = Password::new(phrase.as_bytes());
    let (state, pake_msg_1) =
        Spake2::<Ed25519Group>::start_a(&password, &Identity::new(ID_A), &Identity::new(ID_B));

    let mut h = Hasher::new();
    h.update(DOMAIN_SENDER_COMMITMENT);
    h.update(&share_id);
    h.update(&pake_msg_1);
    let sender_commitment = *h.finalize().as_bytes();

    SenderPakeState {
        state,
        offer: SenderOffer {
            version: PHRASE_PROTOCOL_VERSION,
            share_id,
            sender_commitment,
            pake_msg_1,
            created_at_ms: now_ms,
            expires_at_ms,
        },
    }
}

pub fn new_receiver_commitment(
    share_id: [u8; 32],
    sender_commitment: [u8; 32],
    pake_msg_2: &[u8],
) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(DOMAIN_RECEIVER_COMMITMENT);
    h.update(&share_id);
    h.update(&sender_commitment);
    h.update(pake_msg_2);
    *h.finalize().as_bytes()
}

pub fn receiver_start_pake(phrase: &str, offer: &SenderOffer) -> ReceiverPakeState {
    let password = Password::new(phrase.as_bytes());
    let (state, pake_msg_2) =
        Spake2::<Ed25519Group>::start_b(&password, &Identity::new(ID_A), &Identity::new(ID_B));

    let receiver_commitment =
        new_receiver_commitment(offer.share_id, offer.sender_commitment, &pake_msg_2);
    ReceiverPakeState {
        state,
        hello: ReceiverHello {
            version: PHRASE_PROTOCOL_VERSION,
            share_id: offer.share_id,
            sender_commitment: offer.sender_commitment,
            receiver_commitment,
            pake_msg_2,
        },
    }
}

/// Derives a session key from the PAKE secret and the transcript of the PAKE messages.
fn derive_session_key(
    pake_secret: &[u8],
    share_id: [u8; 32],
    sender_commitment: [u8; 32],
    receiver_commitment: [u8; 32],
    pake_msg_1: &[u8],
    pake_msg_2: &[u8],
) -> Result<[u8; 32]> {
    let mut transcript = Hasher::new();
    transcript.update(DOMAIN_KDF);
    transcript.update(&share_id);
    transcript.update(&sender_commitment);
    transcript.update(&receiver_commitment);
    transcript.update(pake_msg_2);
    transcript.update(pake_msg_1);
    let transcript_hash = transcript.finalize();

    let hk = Hkdf::<Sha256>::new(Some(transcript_hash.as_bytes()), pake_secret);
    let mut out = [0u8; 32];
    hk.expand(DOMAIN_KDF, &mut out)
        .map_err(|_| anyhow!("hkdf expand failed"))?;
    Ok(out)
}

pub fn sender_finish_pake(state: SenderPakeState, hello: &ReceiverHello) -> Result<[u8; 32]> {
    let pake_secret = Zeroizing::new(
        state
            .state
            .finish(&hello.pake_msg_2)
            .map_err(|_| anyhow!("SPAKE2 sender finish failed"))?,
    );

    derive_session_key(
        &pake_secret,
        state.offer.share_id,
        state.offer.sender_commitment,
        hello.receiver_commitment,
        &state.offer.pake_msg_1,
        &hello.pake_msg_2,
    )
}

pub fn receiver_finish_pake(state: ReceiverPakeState, offer: &SenderOffer) -> Result<[u8; 32]> {
    let pake_secret = Zeroizing::new(
        state
            .state
            .finish(&offer.pake_msg_1)
            .map_err(|_| anyhow!("SPAKE2 receiver finish failed"))?,
    );

    derive_session_key(
        &pake_secret,
        offer.share_id,
        offer.sender_commitment,
        state.hello.receiver_commitment,
        &offer.pake_msg_1,
        &state.hello.pake_msg_2,
    )
}

fn aad_bytes(
    share_id: [u8; 32],
    sender_commitment: [u8; 32],
    receiver_commitment: [u8; 32],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 32 * 3);
    out.extend_from_slice(&share_id);
    out.extend_from_slice(&sender_commitment);
    out.extend_from_slice(&receiver_commitment);
    out
}

pub fn encrypt_ticket_envelope(
    session_key: [u8; 32],
    share_id: [u8; 32],
    sender_commitment: [u8; 32],
    receiver_commitment: [u8; 32],
    envelope: &TicketEnvelope,
) -> Result<([u8; 24], Vec<u8>)> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&session_key));
    let plaintext = postcard::to_stdvec(envelope)?;
    let mut nonce = [0u8; 24];
    rand::rng().fill_bytes(&mut nonce);

    let aad = aad_bytes(share_id, sender_commitment, receiver_commitment);
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| anyhow!("encrypt envelope failed"))?;
    Ok((nonce, ciphertext))
}

pub fn decrypt_ticket_envelope(
    session_key: [u8; 32],
    share_id: [u8; 32],
    sender_commitment: [u8; 32],
    receiver_commitment: [u8; 32],
    nonce: [u8; 24],
    ciphertext: &[u8],
) -> Result<TicketEnvelope> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&session_key));
    let aad = aad_bytes(share_id, sender_commitment, receiver_commitment);
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| anyhow!("decrypt ticket envelope failed"))?;
    Ok(postcard::from_bytes(&plaintext)?)
}

pub fn derive_ack_tag(
    session_key: [u8; 32],
    share_id: [u8; 32],
    sender_commitment: [u8; 32],
    receiver_commitment: [u8; 32],
) -> Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(&session_key), DOMAIN_ACK);
    let mut ack_key = [0u8; 32];
    hk.expand(DOMAIN_ACK, &mut ack_key)
        .map_err(|_| anyhow!("ack hkdf expand failed"))?;
    let hash = blake3::keyed_hash(
        &ack_key,
        &[
            &share_id[..],
            &sender_commitment[..],
            &receiver_commitment[..],
        ]
        .concat(),
    );
    Ok(*hash.as_bytes())
}
