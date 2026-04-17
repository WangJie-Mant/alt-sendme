use anyhow::{bail, Result};
use distributed_topic_tracker::{AutoDiscoveryGossip, RecordPublisher};
use ed25519_dalek::SigningKey;
use iroh_96::{protocol::Router, Endpoint, RelayMode, SecretKey};
use iroh_gossip_96::{api::Event, net::Gossip};
use n0_future::task::AbortOnDropHandle;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use tokio::time::{Duration, Instant};
use tracing::{info, warn};

use crate::core::types::{PhraseResolveOptions, PhraseShareOptions};

use super::phrase_crypto::{
    decrypt_ticket_envelope, derive_ack_tag, derive_share_id, derive_topic_id,
    encrypt_ticket_envelope, new_sender_offer, receiver_finish_pake, receiver_start_pake,
    sender_finish_pake, TicketEnvelope,
};
use super::phrase_proto::{
    PhraseMessage, ReceiverAck, ReceiverHello, SenderOffer, SenderTicket, PHRASE_PROTOCOL_VERSION,
};

const JOIN_WAIT_TIMEOUT: Duration = Duration::from_secs(25);
const JOIN_POLL_INTERVAL: Duration = Duration::from_millis(500);
const RECEIVER_ATTEMPT_BUDGET: Duration = Duration::from_secs(25);
const RECEIVER_REBUILD_DELAY: Duration = Duration::from_millis(800);
const RECEIVER_OFFER_IDLE_REBUILD: Duration = Duration::from_secs(10);

pub struct PhraseControlPlane {
    pub endpoint: Endpoint,
    pub gossip: Gossip,
    pub router: Router,
    pub topic: distributed_topic_tracker::Topic,
}

pub async fn open_control_plane(phrase: &str, relay_mode: RelayMode) -> Result<PhraseControlPlane> {
    let secret_key = SecretKey::generate(&mut rand::rng());
    let signing_key = SigningKey::from_bytes(&secret_key.to_bytes());

    // Prefer IPv4 binding for phrase control-plane to avoid unstable IPv6 MTU paths
    // observed on some networks (e.g. repeated WSAEMSGSIZE / sendmsg 10040).
    let bind_v4 = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0);

    let endpoint = Endpoint::builder()
        .secret_key(secret_key)
        .relay_mode(relay_mode)
        .bind_addr(SocketAddr::V4(bind_v4))?
        .bind()
        .await?;

    let gossip = Gossip::builder().spawn(endpoint.clone());
    let router = Router::builder(endpoint.clone())
        .accept(iroh_gossip_96::ALPN, gossip.clone())
        .spawn();

    let topic_id = derive_topic_id(phrase);
    let topic_hash = topic_id.hash();
    info!(
        phrase_len = phrase.len(),
        topic_prefix = %short_hex(&topic_hash, 6),
        bind_v4 = %bind_v4,
        "phrase control plane opening"
    );
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

    info!(
        topic_prefix = %short_hex(&topic_hash, 6),
        "phrase control plane ready"
    );

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
        info!(
            phrase_len = phrase_opts.phrase.len(),
            announce_ms = phrase_opts.announce_interval.as_millis() as u64,
            timeout_secs = phrase_opts.handoff_timeout.as_secs(),
            "phrase sender handoff started"
        );
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
        if !wait_for_join("sender", &gossip_receiver, JOIN_WAIT_TIMEOUT).await? {
            warn!("phrase sender did not observe joined gossip mesh before handoff loop");
        }
        let offer = sender_state
            .as_ref()
            .expect("sender state initialized")
            .offer
            .clone();
        let offer_bytes = postcard::to_stdvec(&PhraseMessage::SenderOffer(offer.clone()))?;

        let mut interval = tokio::time::interval(phrase_opts.announce_interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let deadline = Instant::now() + phrase_opts.handoff_timeout;
        let mut offer_tick_count: u64 = 0;

        info!("phrase sender waiting for receiver hello");

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    offer_tick_count += 1;
                    if offer_tick_count == 1 || offer_tick_count % 20 == 0 {
                        let is_joined = gossip_receiver.is_joined().await;
                        let neighbors = gossip_receiver.neighbors().await.len();
                        info!(
                            offer_broadcasts = offer_tick_count,
                            is_joined,
                            neighbors,
                            "phrase sender broadcasting offer"
                        );
                    }
                    broadcast_phrase_message(&gossip_sender, &offer_bytes, "sender offer").await?;
                }
                maybe_event = gossip_receiver.next() => {
                    match maybe_event {
                        Some(Ok(Event::Received(msg))) => {
                            let msg_len = msg.content.len();
                            let parsed: PhraseMessage = match postcard::from_bytes(&msg.content) {
                                Ok(v) => v,
                                Err(error) => {
                                    warn!(msg_len, error = %error, "phrase sender failed to parse gossip message");
                                    continue;
                                }
                            };

                            match parsed {
                                PhraseMessage::ReceiverHello(hello) => {
                                    info!(
                                        share_match = hello.share_id == offer.share_id,
                                        sender_commitment_match = hello.sender_commitment == offer.sender_commitment,
                                        receiver_commitment_prefix = %short_hex(&hello.receiver_commitment, 6),
                                        "phrase sender observed receiver hello"
                                    );

                                    if !matches_receiver_hello(&offer, &hello) {
                                        continue;
                                    }

                                    info!("phrase sender received matching receiver hello");

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
                                    let ticket_bytes = postcard::to_stdvec(&ticket_msg)?;
                                    broadcast_phrase_message(&gossip_sender, &ticket_bytes, "sender ticket").await?;
                                    info!("phrase sender broadcast encrypted ticket");

                                    let ack_expected = derive_ack_tag(
                                        sk,
                                        hello.share_id,
                                        hello.sender_commitment,
                                        hello.receiver_commitment,
                                    )?;
                                    let ack_deadline = Instant::now() + Duration::from_secs(8);
                                    let mut ticket_retry = tokio::time::interval(Duration::from_millis(500));
                                    ticket_retry.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                                    let mut resend_count: u64 = 0;

                                    loop {
                                        tokio::select! {
                                            maybe_ack = gossip_receiver.next() => {
                                                match maybe_ack {
                                                    Some(Ok(Event::Received(msg))) => {
                                                        let msg_len = msg.content.len();
                                                        let parsed: PhraseMessage = match postcard::from_bytes(&msg.content) {
                                                            Ok(v) => v,
                                                            Err(error) => {
                                                                warn!(msg_len, error = %error, "phrase sender failed to parse ack candidate");
                                                                continue;
                                                            }
                                                        };

                                                        match parsed {
                                                            PhraseMessage::ReceiverAck(ack) => {
                                                                info!(
                                                                    ack_share_match = ack.share_id == hello.share_id,
                                                                    ack_commitment_match = ack.receiver_commitment == hello.receiver_commitment,
                                                                    "phrase sender observed receiver ack candidate"
                                                                );
                                                                if ack.version == PHRASE_PROTOCOL_VERSION
                                                                    && ack.share_id == hello.share_id
                                                                    && ack.sender_commitment == hello.sender_commitment
                                                                    && ack.receiver_commitment == hello.receiver_commitment
                                                                    && ack.ack_tag == ack_expected
                                                                {
                                                                    info!("phrase sender received valid receiver ack");
                                                                    return Ok(());
                                                                }
                                                            }
                                                            PhraseMessage::ReceiverHello(other_hello) => {
                                                                info!(
                                                                    share_match = other_hello.share_id == offer.share_id,
                                                                    sender_commitment_match = other_hello.sender_commitment == offer.sender_commitment,
                                                                    "phrase sender observed extra receiver hello while awaiting ack"
                                                                );
                                                            }
                                                            _ => {}
                                                        }
                                                    }
                                                    Some(_) => continue,
                                                    None => bail!("gossip receiver closed"),
                                                }
                                            }
                                            _ = ticket_retry.tick() => {
                                                resend_count += 1;
                                                if resend_count == 1 || resend_count % 10 == 0 {
                                                    info!(resends = resend_count, "phrase sender re-broadcasting encrypted ticket");
                                                }
                                                gossip_sender.broadcast(ticket_bytes.clone().into()).await?;
                                            }
                                            _ = tokio::time::sleep_until(ack_deadline) => {
                                                bail!("phrase handoff ack timeout");
                                            }
                                        }
                                    }
                                }
                                other => {
                                    if offer_tick_count == 1 || offer_tick_count % 20 == 0 {
                                        info!(event = ?other, "phrase sender ignoring non-hello gossip message");
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
    info!(
        phrase_len = phrase_opts.phrase.len(),
        resolve_timeout_secs = phrase_opts.resolve_timeout.as_secs(),
        "phrase receiver resolve started"
    );
    let deadline = Instant::now() + phrase_opts.resolve_timeout;
    let ticket_wait_timeout = Duration::from_secs(12);
    let mut attempt: u32 = 0;

    loop {
        if Instant::now() >= deadline {
            bail!("phrase resolve timeout");
        }

        attempt += 1;
        let remaining = deadline.saturating_duration_since(Instant::now());
        let attempt_budget = remaining.min(RECEIVER_ATTEMPT_BUDGET);
        let attempt_deadline = Instant::now() + attempt_budget;

        info!(
            attempt,
            attempt_budget_secs = attempt_budget.as_secs(),
            "phrase receiver opening control-plane attempt"
        );

        let control = open_control_plane(&phrase_opts.phrase, relay_mode.clone()).await?;
        let (gossip_sender, gossip_receiver) = control.topic.split().await?;

        if !wait_for_join(
            "receiver",
            &gossip_receiver,
            JOIN_WAIT_TIMEOUT.min(attempt_budget),
        )
        .await?
        {
            warn!(
                attempt,
                "phrase receiver did not observe joined gossip mesh before resolve loop"
            );
        }

        let mut offer_count: u64 = 0;
        let mut last_offer_seen = Instant::now();
        let mut heartbeat = tokio::time::interval(Duration::from_secs(5));
        heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                maybe_event = gossip_receiver.next() => {
                    match maybe_event {
                        Some(Ok(Event::Received(msg))) => {
                            let msg_len = msg.content.len();
                            let parsed: PhraseMessage = match postcard::from_bytes(&msg.content) {
                                Ok(v) => v,
                                Err(error) => {
                                    warn!(msg_len, error = %error, "phrase receiver failed to parse gossip message");
                                    continue;
                                }
                            };

                            if let PhraseMessage::SenderOffer(offer) = parsed {
                                offer_count += 1;
                                last_offer_seen = Instant::now();

                                if offer_count == 1 || offer_count % 20 == 0 {
                                    info!(offers_seen = offer_count, attempt, "phrase receiver observed sender offers");
                                }

                                if offer.version != PHRASE_PROTOCOL_VERSION {
                                    warn!("ignoring offer with unsupported protocol version");
                                    continue;
                                }
                                if offer.expires_at_ms < now_ms() {
                                    continue;
                                }

                                let receiver_state = receiver_start_pake(&phrase_opts.phrase, &offer);
                                let receiver_hello = receiver_state.hello.clone();
                                let expected_receiver_commitment = receiver_hello.receiver_commitment;
                                let sk = match receiver_finish_pake(receiver_state, &offer) {
                                    Ok(key) => key,
                                    Err(e) => {
                                        warn!(error = %e, "phrase receiver failed to finish PAKE for offer");
                                        continue;
                                    }
                                };
                                let hello_bytes = postcard::to_stdvec(&PhraseMessage::ReceiverHello(
                                    receiver_hello.clone(),
                                ))?;
                                broadcast_phrase_message(&gossip_sender, &hello_bytes, "receiver hello").await?;

                                info!("phrase receiver sent receiver hello; waiting for sender ticket");

                                let wait_deadline = (Instant::now() + ticket_wait_timeout).min(attempt_deadline);
                                let mut hello_retry = tokio::time::interval(Duration::from_millis(500));
                                hello_retry.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                                let mut resend_count: u64 = 0;

                                loop {
                                    tokio::select! {
                                        maybe_ticket = gossip_receiver.next() => {
                                            match maybe_ticket {
                                                Some(Ok(Event::Received(msg))) => {
                                                    let parsed: PhraseMessage = match postcard::from_bytes(&msg.content) {
                                                        Ok(v) => v,
                                                        Err(_) => continue,
                                                    };

                                                    if let PhraseMessage::SenderTicket(ticket_msg) = parsed {
                                                        if ticket_msg.version != PHRASE_PROTOCOL_VERSION
                                                            || ticket_msg.share_id != offer.share_id
                                                            || ticket_msg.sender_commitment != offer.sender_commitment
                                                            || ticket_msg.receiver_commitment != expected_receiver_commitment
                                                        {
                                                            continue;
                                                        }

                                                        let envelope = match decrypt_ticket_envelope(
                                                            sk,
                                                            ticket_msg.share_id,
                                                            ticket_msg.sender_commitment,
                                                            ticket_msg.receiver_commitment,
                                                            ticket_msg.nonce,
                                                            &ticket_msg.ciphertext,
                                                        ) {
                                                            Ok(v) => v,
                                                            Err(e) => {
                                                                warn!(error = %e, "phrase receiver failed to decrypt sender ticket");
                                                                continue;
                                                            }
                                                        };

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
                                                        let ack_bytes = postcard::to_stdvec(&ack)?;
                                                        broadcast_phrase_message(&gossip_sender, &ack_bytes, "receiver ack").await?;
                                                        info!("phrase receiver decrypted ticket and sent ack");
                                                        return Ok(envelope.ticket);
                                                    }
                                                }
                                                Some(_) => continue,
                                                None => bail!("gossip receiver closed"),
                                            }
                                        }
                                        _ = hello_retry.tick() => {
                                            resend_count += 1;
                                            if resend_count == 1 || resend_count % 10 == 0 {
                                                info!(resends = resend_count, "phrase receiver re-broadcasting hello");
                                            }
                                            broadcast_phrase_message(&gossip_sender, &hello_bytes, "receiver hello retry").await?;
                                        }
                                        _ = tokio::time::sleep_until(wait_deadline) => {
                                            info!(attempt, "phrase receiver timed out waiting sender ticket for current offer; retrying offer scan");
                                            break;
                                        }
                                        _ = tokio::time::sleep_until(deadline) => {
                                            bail!("phrase resolve timeout");
                                        }
                                    }
                                }
                            }
                        }
                        Some(_) => {}
                        None => bail!("gossip receiver closed"),
                    }
                }
                _ = heartbeat.tick() => {
                    let is_joined = gossip_receiver.is_joined().await;
                    let neighbors = gossip_receiver.neighbors().await.len();
                    info!(is_joined, neighbors, offers_seen = offer_count, attempt, "phrase receiver waiting for offers");

                    if is_joined
                        && offer_count == 0
                        && last_offer_seen.elapsed() >= RECEIVER_OFFER_IDLE_REBUILD
                    {
                        info!(attempt, idle_secs = RECEIVER_OFFER_IDLE_REBUILD.as_secs(), "phrase receiver joined but no offers observed; rebuilding control-plane");
                        break;
                    }
                }
                _ = tokio::time::sleep_until(attempt_deadline) => {
                    info!(attempt, "phrase receiver attempt budget elapsed; rebuilding control-plane");
                    break;
                }
                _ = tokio::time::sleep_until(deadline) => {
                    bail!("phrase resolve timeout");
                }
            }
        }

        drop(control);

        tokio::time::sleep(
            RECEIVER_REBUILD_DELAY.min(deadline.saturating_duration_since(Instant::now())),
        )
        .await;
        continue;
    }
}

async fn wait_for_join(
    role: &str,
    gossip_receiver: &distributed_topic_tracker::GossipReceiver,
    timeout: Duration,
) -> Result<bool> {
    let start = Instant::now();
    let deadline = start + timeout;

    loop {
        let is_joined = gossip_receiver.is_joined().await;
        let neighbors = gossip_receiver.neighbors().await.len();
        if is_joined {
            info!(
                role,
                neighbors,
                elapsed_ms = start.elapsed().as_millis() as u64,
                "phrase gossip joined"
            );
            return Ok(true);
        }

        if Instant::now() >= deadline {
            info!(
                role,
                neighbors,
                waited_ms = timeout.as_millis() as u64,
                "phrase gossip join wait elapsed"
            );
            return Ok(false);
        }

        tokio::time::sleep(JOIN_POLL_INTERVAL).await;
    }
}

fn short_hex(bytes: &[u8], take: usize) -> String {
    bytes
        .iter()
        .take(take)
        .map(|b| format!("{:02x}", b))
        .collect::<String>()
}

async fn broadcast_phrase_message(
    gossip_sender: &distributed_topic_tracker::GossipSender,
    bytes: &[u8],
    label: &str,
) -> Result<()> {
    let payload = bytes.to_vec();

    if let Err(error) = gossip_sender.broadcast(payload.clone()).await {
        warn!(label, error = %error, "phrase broadcast failed");
    }

    if let Err(error) = gossip_sender.broadcast_neighbors(payload).await {
        warn!(label, error = %error, "phrase neighbor broadcast failed");
    }

    Ok(())
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
