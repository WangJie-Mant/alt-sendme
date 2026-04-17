use anyhow::{bail, Result};
use distributed_topic_tracker::{AutoDiscoveryGossip, RecordPublisher};
use ed25519_dalek::SigningKey;
use iroh_96::{protocol::Router, Endpoint, RelayMode, SecretKey};
use iroh_gossip_96::{api::Event, net::Gossip};
use n0_future::task::AbortOnDropHandle;
use tokio::time::{Duration, Instant};
use tracing::warn;

use crate::core::types::{PhraseResolveOptions, PhraseShareOptions};

use super::phrase_crypto::{
    decrypt_ticket_envelope, derive_ack_tag, derive_share_id, derive_topic_id,
    encrypt_ticket_envelope, new_sender_offer, receiver_finish_pake, receiver_start_pake,
    sender_finish_pake, TicketEnvelope,
};
use super::phrase_proto::{
    PhraseMessage, ReceiverAck, ReceiverHello, SenderOffer, SenderTicket, PHRASE_PROTOCOL_VERSION,
};

pub struct PhraseControlPlane {
    pub endpoint: Endpoint,
    pub gossip: Gossip,
    pub router: Router,
    pub topic: distributed_topic_tracker::Topic,
}

pub async fn open_control_plane(phrase: &str, relay_mode: RelayMode) -> Result<PhraseControlPlane> {
    let secret_key = SecretKey::generate(&mut rand::rng());
    let signing_key = SigningKey::from_bytes(&secret_key.to_bytes());

    let endpoint = Endpoint::builder()
        .secret_key(secret_key)
        .relay_mode(relay_mode)
        .bind()
        .await?;

    let gossip = Gossip::builder().spawn(endpoint.clone());
    let router = Router::builder(endpoint.clone())
        .accept(iroh_gossip_96::ALPN, gossip.clone())
        .spawn();

    let topic_id = derive_topic_id(phrase);
    let record_publisher = RecordPublisher::new(
        topic_id,
        signing_key.verifying_key(),
        signing_key,
        None,
        phrase.as_bytes().to_vec(),
    );

    let topic = gossip
        .subscribe_and_join_with_auto_discovery_no_wait(record_publisher)
        .await?;

    Ok(PhraseControlPlane {
        endpoint,
        gossip,
        router,
        topic,
    })
}

pub fn spawn_sender_phrase_handoff(
    phrase_opts: PhraseShareOptions,
    relay_mode: RelayMode,
    ticket: String,
    ticket_hash: String,
) -> Result<AbortOnDropHandle<anyhow::Result<()>>> {
    let task = tokio::spawn(async move {
        let control = open_control_plane(&phrase_opts.phrase, relay_mode).await?;
        let share_id = derive_share_id(&ticket);
        let created_at_ms = now_ms();
        let mut sender_state = Some(new_sender_offer(
            &phrase_opts.phrase,
            share_id,
            created_at_ms,
            created_at_ms + phrase_opts.handoff_timeout.as_millis() as u64,
        ));

        let (gossip_sender, gossip_receiver) = control.topic.split().await?;
        let offer = sender_state
            .as_ref()
            .expect("sender state initialized")
            .offer
            .clone();
        let offer_bytes = postcard::to_stdvec(&PhraseMessage::SenderOffer(offer.clone()))?;

        let mut interval = tokio::time::interval(phrase_opts.announce_interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let deadline = Instant::now() + phrase_opts.handoff_timeout;

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    gossip_sender.broadcast(offer_bytes.clone().into()).await?;
                }
                maybe_event = gossip_receiver.next() => {
                    match maybe_event {
                        Some(Ok(Event::Received(msg))) => {
                            let parsed: PhraseMessage = match postcard::from_bytes(&msg.content) {
                                Ok(v) => v,
                                Err(_) => continue,
                            };

                            if let PhraseMessage::ReceiverHello(hello) = parsed {
                                if !matches_receiver_hello(&offer, &hello) {
                                    continue;
                                }

                                let state = sender_state
                                    .take()
                                    .expect("sender state consumed only once after first valid hello");
                                let sk = sender_finish_pake(state, &hello)?;
                                let envelope = TicketEnvelope {
                                    ticket: ticket.clone(),
                                    ticket_hash: ticket_hash.clone(),
                                    issued_at_ms: now_ms(),
                                };
                                let (nonce, ciphertext) = encrypt_ticket_envelope(
                                    sk,
                                    hello.share_id,
                                    hello.sender_commitment,
                                    hello.receiver_commitment,
                                    &envelope,
                                )?;
                                let ticket_msg = PhraseMessage::SenderTicket(SenderTicket {
                                    version: PHRASE_PROTOCOL_VERSION,
                                    share_id: hello.share_id,
                                    sender_commitment: hello.sender_commitment,
                                    receiver_commitment: hello.receiver_commitment,
                                    nonce,
                                    ciphertext,
                                });
                                gossip_sender
                                    .broadcast(postcard::to_stdvec(&ticket_msg)?.into())
                                    .await?;

                                let ack_expected = derive_ack_tag(
                                    sk,
                                    hello.share_id,
                                    hello.sender_commitment,
                                    hello.receiver_commitment,
                                )?;
                                let ack_deadline = Instant::now() + Duration::from_secs(8);

                                loop {
                                    if Instant::now() >= ack_deadline {
                                        bail!("phrase handoff ack timeout");
                                    }

                                    match gossip_receiver.next().await {
                                        Some(Ok(Event::Received(msg))) => {
                                            let parsed: PhraseMessage = match postcard::from_bytes(&msg.content) {
                                                Ok(v) => v,
                                                Err(_) => continue,
                                            };

                                            if let PhraseMessage::ReceiverAck(ack) = parsed {
                                                if ack.version == PHRASE_PROTOCOL_VERSION
                                                    && ack.share_id == hello.share_id
                                                    && ack.sender_commitment == hello.sender_commitment
                                                    && ack.receiver_commitment == hello.receiver_commitment
                                                    && ack.ack_tag == ack_expected
                                                {
                                                    return Ok(());
                                                }
                                            }
                                        }
                                        Some(_) => continue,
                                        None => bail!("gossip receiver closed"),
                                    }
                                }
                            }
                        }
                        Some(_) => {}
                        None => bail!("gossip receiver closed"),
                    }
                }
                _ = tokio::time::sleep_until(deadline) => {
                    bail!("phrase handoff timeout");
                }
            }
        }
    });

    Ok(AbortOnDropHandle::new(task))
}

pub async fn resolve_phrase_ticket(
    phrase_opts: PhraseResolveOptions,
    relay_mode: RelayMode,
) -> Result<String> {
    let control = open_control_plane(&phrase_opts.phrase, relay_mode).await?;
    let (gossip_sender, gossip_receiver) = control.topic.split().await?;
    let deadline = Instant::now() + phrase_opts.resolve_timeout;

    loop {
        tokio::select! {
            maybe_event = gossip_receiver.next() => {
                match maybe_event {
                    Some(Ok(Event::Received(msg))) => {
                        let parsed: PhraseMessage = match postcard::from_bytes(&msg.content) {
                            Ok(v) => v,
                            Err(_) => continue,
                        };

                        if let PhraseMessage::SenderOffer(offer) = parsed {
                            if offer.version != PHRASE_PROTOCOL_VERSION {
                                warn!("ignoring offer with unsupported protocol version");
                                continue;
                            }
                            if offer.expires_at_ms < now_ms() {
                                continue;
                            }

                            let receiver_state = receiver_start_pake(&phrase_opts.phrase, &offer);
                            gossip_sender
                                .broadcast(
                                    postcard::to_stdvec(&PhraseMessage::ReceiverHello(
                                        receiver_state.hello.clone(),
                                    ))?
                                    .into(),
                                )
                                .await?;

                            loop {
                                match gossip_receiver.next().await {
                                    Some(Ok(Event::Received(msg))) => {
                                        let parsed: PhraseMessage = match postcard::from_bytes(&msg.content) {
                                            Ok(v) => v,
                                            Err(_) => continue,
                                        };

                                        if let PhraseMessage::SenderTicket(ticket_msg) = parsed {
                                            if ticket_msg.version != PHRASE_PROTOCOL_VERSION
                                                || ticket_msg.share_id != offer.share_id
                                                || ticket_msg.sender_commitment != offer.sender_commitment
                                                || ticket_msg.receiver_commitment != receiver_state.hello.receiver_commitment
                                            {
                                                continue;
                                            }

                                            let sk = receiver_finish_pake(receiver_state, &offer)?;
                                            let envelope = decrypt_ticket_envelope(
                                                sk,
                                                ticket_msg.share_id,
                                                ticket_msg.sender_commitment,
                                                ticket_msg.receiver_commitment,
                                                ticket_msg.nonce,
                                                &ticket_msg.ciphertext,
                                            )?;

                                            let ack_tag = derive_ack_tag(
                                                sk,
                                                ticket_msg.share_id,
                                                ticket_msg.sender_commitment,
                                                ticket_msg.receiver_commitment,
                                            )?;
                                            let ack = PhraseMessage::ReceiverAck(ReceiverAck {
                                                version: PHRASE_PROTOCOL_VERSION,
                                                share_id: ticket_msg.share_id,
                                                sender_commitment: ticket_msg.sender_commitment,
                                                receiver_commitment: ticket_msg.receiver_commitment,
                                                ack_tag,
                                            });
                                            gossip_sender
                                                .broadcast(postcard::to_stdvec(&ack)?.into())
                                                .await?;
                                            return Ok(envelope.ticket);
                                        }
                                    }
                                    Some(_) => continue,
                                    None => bail!("gossip receiver closed"),
                                }
                            }
                        }
                    }
                    Some(_) => {}
                    None => bail!("gossip receiver closed"),
                }
            }
            _ = tokio::time::sleep_until(deadline) => {
                bail!("phrase resolve timeout");
            }
        }
    }
}

fn matches_receiver_hello(offer: &SenderOffer, hello: &ReceiverHello) -> bool {
    hello.version == PHRASE_PROTOCOL_VERSION
        && hello.share_id == offer.share_id
        && hello.sender_commitment == offer.sender_commitment
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_millis() as u64
}
