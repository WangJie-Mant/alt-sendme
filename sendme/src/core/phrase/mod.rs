pub mod phrase;
pub mod phrase_crypto;
pub mod phrase_proto;

pub use phrase::{resolve_phrase_ticket, spawn_sender_phrase_handoff, PhraseControlPlane};
pub use phrase_crypto::{
    decrypt_ticket_envelope, derive_ack_tag, derive_share_id, derive_topic_id,
    encrypt_ticket_envelope, new_receiver_commitment, new_sender_offer, receiver_finish_pake,
    receiver_start_pake, sender_finish_pake, TicketEnvelope,
};
pub use phrase_proto::{
    PhraseMessage, ReceiverAck, ReceiverHello, SenderOffer, SenderTicket, PHRASE_PROTOCOL_VERSION,
};
