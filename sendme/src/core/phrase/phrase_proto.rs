use serde::{Deserialize, Serialize};

pub const PHRASE_PROTOCOL_VERSION: u8 = 1;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum PhraseMessage {
    SenderOffer(SenderOffer),
    ReceiverHello(ReceiverHello),
    SenderTicket(SenderTicket),
    ReceiverAck(ReceiverAck),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SenderOffer {
    pub version: u8,
    pub share_id: [u8; 32],
    pub sender_commitment: [u8; 32],
    #[serde(with = "serde_bytes")]
    pub pake_msg_1: Vec<u8>,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ReceiverHello {
    pub version: u8,
    pub share_id: [u8; 32],
    pub sender_commitment: [u8; 32],
    pub receiver_commitment: [u8; 32],
    #[serde(with = "serde_bytes")]
    pub pake_msg_2: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SenderTicket {
    pub version: u8,
    pub share_id: [u8; 32],
    pub sender_commitment: [u8; 32],
    pub receiver_commitment: [u8; 32],
    pub nonce: [u8; 24],
    #[serde(with = "serde_bytes")]
    pub ciphertext: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ReceiverAck {
    pub version: u8,
    pub share_id: [u8; 32],
    pub sender_commitment: [u8; 32],
    pub receiver_commitment: [u8; 32],
    pub ack_tag: [u8; 32],
}
