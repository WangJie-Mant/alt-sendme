use anyhow::{bail, Result};
use distributed_topic_tracker::{AutoDiscoveryGossip, RecordPublisher};
use ed25519_dalek::SigningKey;
use iroh_96::{protocol::Router, Endpoint, RelayMode, SecretKey};
use iroh_gossip_96::{api::Event, net::Gossip};
use n0_future::task::AbortOnDropHandle;
use n0_future::StreamExt;
use tokio::time::{Duration, Instant};
use tracing::{info, warn};

use crate::core::types::{PhraseResolveOptions, PhraseShareOptions};

use super::phrase_crypto::{
    decrypt_ticket_envelope, derive_ack_tag, derive_share_id, derive_topic_id,
    encrypt_ticket_envelope, new_sender_offer, receiver_finish_pake, receiver_start_pake,
    sender_finish_pake, SenderPakeState, TicketEnvelope,
};
use super::phrase_proto::{
    PhraseMessage, ReceiverAck, ReceiverHello, SenderOffer, SenderTicket, PHRASE_PROTOCOL_VERSION,
};

enum SenderPhase {
    AwaitHello {
        sender_state: Option<SenderPakeState>,
        offer: SenderOffer,
        offer_bytes: Vec<u8>,
    },
    AwaitAck {
        hello: ReceiverHello,
        ack_expected: [u8; 32],
        ticket_bytes: Vec<u8>,
        ack_deadline: Instant,
        resend_count: u64,
    },
}

enum ReceiverPhase {
    AwaitOffer,
    AwaitTicket {
        offer: SenderOffer,
        expected_receiver_commitment: [u8; 32],
        sk: [u8; 32],
        hello_bytes: Vec<u8>,
        wait_deadline: Instant,
        resend_count: u64,
    },
}

fn build_sender_offer(
    phrase: &str,
    share_id: [u8; 32],
    handoff_timeout: Duration,
) -> Result<(SenderPakeState, SenderOffer, Vec<u8>)> {
    let created_at_ms = now_ms();
    let sender_state = new_sender_offer(
        phrase,
        share_id,
        created_at_ms,
        created_at_ms + handoff_timeout.as_millis() as u64,
    );
    let offer = sender_state.offer.clone();
    let offer_bytes = postcard::to_stdvec(&PhraseMessage::SenderOffer(offer.clone()))?;
    Ok((sender_state, offer, offer_bytes))
}

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
    let topic_hash = topic_id.hash();
    info!(
        phrase_len = phrase.len(),
        topic_prefix = %short_hex(&topic_hash, 6),
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
        let topic_id = derive_topic_id(&phrase_opts.phrase);
        let topic_hash = topic_id.hash();

        let (gossip_sender, gossip_receiver_raw) = control.topic.split().await?;
        let status_receiver = gossip_receiver_raw.clone();

        let (tx, mut gossip_receiver) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Some(evt) = gossip_receiver_raw.next().await {
                let _ = tx.send(evt);
            }
        });

        let (sender_state, offer, offer_bytes) =
            build_sender_offer(&phrase_opts.phrase, share_id, phrase_opts.handoff_timeout)?;
        let mut phase = SenderPhase::AwaitHello {
            sender_state: Some(sender_state),
            offer,
            offer_bytes,
        };

        let mut heartbeat = tokio::time::interval(Duration::from_secs(5));
        heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        let mut offer_interval = tokio::time::interval(phrase_opts.announce_interval);
        offer_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut retry_interval = tokio::time::interval(Duration::from_millis(500));
        retry_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let deadline = Instant::now() + phrase_opts.handoff_timeout;
        let mut offer_tick_count: u64 = 0;

        info!("phrase sender waiting for receiver hello");

        loop {
            tokio::select! {
                _ = heartbeat.tick() => {
                    let is_joined = status_receiver.is_joined().await;
                    let neighbors = status_receiver.neighbors().await;
                    info!(
                        role = "sender",
                        topic = %short_hex(&topic_hash, 32),
                        joined = is_joined,
                        neighbor_count = neighbors.len(),
                        neighbors = ?neighbors,
                        "gossip status heartbeat"
                    );
                }
                _ = offer_interval.tick() => {
                    if let SenderPhase::AwaitHello { offer_bytes, .. } = &phase {
                        offer_tick_count += 1;
                        if offer_tick_count == 1 || offer_tick_count % 20 == 0 {
                            let is_joined = status_receiver.is_joined().await;
                            let neighbors = status_receiver.neighbors().await.len();
                            info!(
                                offer_broadcasts = offer_tick_count,
                                is_joined,
                                neighbors,
                                "phrase sender broadcasting offer"
                            );
                        }
                        broadcast_phrase_message(&gossip_sender, offer_bytes, "sender offer").await?;
                    }
                }
                _ = retry_interval.tick() => {
                    if let SenderPhase::AwaitAck { ticket_bytes, resend_count, .. } = &mut phase {
                        *resend_count += 1;
                        if *resend_count == 1 || *resend_count % 10 == 0 {
                            info!(resends = *resend_count, "phrase sender re-broadcasting encrypted ticket");
                        }
                        broadcast_phrase_message(&gossip_sender, ticket_bytes, "sender ticket retry").await?;
                    }
                }
                maybe_event = gossip_receiver.recv() => {
                    match maybe_event {
                        Some(Ok(event)) => {
                            log_gossip_event("sender", &event);
                            if let Event::Received(msg) = event {
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
                                        match &mut phase {
                                            SenderPhase::AwaitHello { sender_state, offer, .. } => {
                                                info!(
                                                    share_match = hello.share_id == offer.share_id,
                                                    sender_commitment_match = hello.sender_commitment == offer.sender_commitment,
                                                    receiver_commitment_prefix = %short_hex(&hello.receiver_commitment, 6),
                                                    "phrase sender observed receiver hello"
                                                );

                                                if !matches_receiver_hello(offer, &hello) {
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
                                                phase = SenderPhase::AwaitAck {
                                                    hello,
                                                    ack_expected,
                                                    ticket_bytes,
                                                    ack_deadline: Instant::now() + Duration::from_secs(8),
                                                    resend_count: 0,
                                                };
                                            }
                                            SenderPhase::AwaitAck { hello: active_hello, ticket_bytes, .. } => {
                                                if hello.share_id == active_hello.share_id
                                                    && hello.sender_commitment == active_hello.sender_commitment
                                                    && hello.receiver_commitment == active_hello.receiver_commitment
                                                {
                                                    info!("phrase sender observed duplicate receiver hello while awaiting ack");
                                                    broadcast_phrase_message(&gossip_sender, ticket_bytes, "sender ticket duplicate-hello").await?;
                                                }
                                            }
                                        }
                                    }
                                    PhraseMessage::ReceiverAck(ack) => {
                                        if let SenderPhase::AwaitAck {
                                            hello,
                                            ack_expected,
                                            ..
                                        } = &phase {
                                            info!(
                                                ack_share_match = ack.share_id == hello.share_id,
                                                ack_commitment_match = ack.receiver_commitment == hello.receiver_commitment,
                                                "phrase sender observed receiver ack candidate"
                                            );
                                            if ack.version == PHRASE_PROTOCOL_VERSION
                                                && ack.share_id == hello.share_id
                                                && ack.sender_commitment == hello.sender_commitment
                                                && ack.receiver_commitment == hello.receiver_commitment
                                                && ack.ack_tag == *ack_expected
                                            {
                                                info!("phrase sender received valid receiver ack");
                                                return Ok(());
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
                        }
                        Some(Err(error)) => {
                            warn!(error = %error, "phrase sender gossip stream error");
                        }
                        None => bail!("gossip receiver closed"),
                    }
                }
                _ = tokio::time::sleep_until(deadline) => {
                    bail!("phrase handoff timeout");
                }
            }

            if let SenderPhase::AwaitAck { ack_deadline, .. } = &phase {
                if Instant::now() >= *ack_deadline {
                    warn!("phrase sender ack timeout; rotating sender offer state");
                    let (new_state, new_offer, new_offer_bytes) = build_sender_offer(
                        &phrase_opts.phrase,
                        share_id,
                        phrase_opts.handoff_timeout,
                    )?;
                    phase = SenderPhase::AwaitHello {
                        sender_state: Some(new_state),
                        offer: new_offer,
                        offer_bytes: new_offer_bytes,
                    };
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

    info!("phrase receiver opening stable control-plane session");
    let control = open_control_plane(&phrase_opts.phrase, relay_mode).await?;
    let (gossip_sender, gossip_receiver_raw) = control.topic.split().await?;
    let status_receiver = gossip_receiver_raw.clone();
    let (tx, mut gossip_receiver) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Some(evt) = gossip_receiver_raw.next().await {
            let _ = tx.send(evt);
        }
    });
    let topic_id = derive_topic_id(&phrase_opts.phrase);
    let topic_hash = topic_id.hash();

    let mut offer_count: u64 = 0;
    let mut heartbeat = tokio::time::interval(Duration::from_secs(5));
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut retry_interval = tokio::time::interval(Duration::from_millis(500));
    retry_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut phase = ReceiverPhase::AwaitOffer;

    loop {
        tokio::select! {
            _ = retry_interval.tick() => {
                if let ReceiverPhase::AwaitTicket { hello_bytes, resend_count, .. } = &mut phase {
                    *resend_count += 1;
                    if *resend_count == 1 || *resend_count % 10 == 0 {
                        info!(resends = *resend_count, "phrase receiver re-broadcasting hello");
                    }
                    broadcast_phrase_message(&gossip_sender, hello_bytes, "receiver hello retry").await?;
                }
            }
            maybe_event = gossip_receiver.recv() => {
                match maybe_event {
                    Some(Ok(event)) => {
                        log_gossip_event("receiver", &event);
                        if let Event::Received(msg) = event {
                            let msg_len = msg.content.len();
                            let parsed: PhraseMessage = match postcard::from_bytes(&msg.content) {
                                Ok(v) => v,
                                Err(error) => {
                                    warn!(msg_len, error = %error, "phrase receiver failed to parse gossip message");
                                    continue;
                                }
                            };

                            match parsed {
                                PhraseMessage::SenderOffer(offer) => {
                                    offer_count += 1;

                                    if offer_count == 1 || offer_count % 20 == 0 {
                                        info!(offers_seen = offer_count, "phrase receiver observed sender offers");
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
                                        receiver_hello,
                                    ))?;
                                    broadcast_phrase_message(&gossip_sender, &hello_bytes, "receiver hello").await?;

                                    info!("phrase receiver sent receiver hello; waiting for sender ticket");
                                    phase = ReceiverPhase::AwaitTicket {
                                        offer,
                                        expected_receiver_commitment,
                                        sk,
                                        hello_bytes,
                                        wait_deadline: (Instant::now() + ticket_wait_timeout).min(deadline),
                                        resend_count: 0,
                                    };
                                }
                                PhraseMessage::SenderTicket(ticket_msg) => {
                                    if let ReceiverPhase::AwaitTicket {
                                        offer,
                                        expected_receiver_commitment,
                                        sk,
                                        ..
                                    } = &phase {
                                        if ticket_msg.version != PHRASE_PROTOCOL_VERSION
                                            || ticket_msg.share_id != offer.share_id
                                            || ticket_msg.sender_commitment != offer.sender_commitment
                                            || ticket_msg.receiver_commitment != *expected_receiver_commitment
                                        {
                                            continue;
                                        }

                                        let envelope = match decrypt_ticket_envelope(
                                            *sk,
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
                                            *sk,
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
                                _ => {}
                            }
                        }
                    }
                    Some(Err(error)) => {
                        warn!(error = %error, "phrase receiver gossip stream error");
                    }
                    None => bail!("gossip receiver closed"),
                }
            }
            _ = heartbeat.tick() => {
                let is_joined = status_receiver.is_joined().await;
                let neighbors = status_receiver.neighbors().await;
                info!(
                    role = "receiver",
                    topic = %short_hex(&topic_hash, 32),
                    joined = is_joined,
                    neighbor_count = neighbors.len(),
                    neighbors = ?neighbors,
                    "gossip status heartbeat"
                );
            }
            _ = tokio::time::sleep_until(deadline) => {
                bail!("phrase resolve timeout");
            }
        }

        if let ReceiverPhase::AwaitTicket { wait_deadline, .. } = &phase {
            if Instant::now() >= *wait_deadline {
                info!("phrase receiver timed out waiting sender ticket for current offer");
                phase = ReceiverPhase::AwaitOffer;
            }
        }
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
    let mut delivered = false;
    let mut first_error: Option<anyhow::Error> = None;

    match gossip_sender.broadcast(payload.clone()).await {
        Ok(_) => {
            delivered = true;
        }
        Err(error) => {
            warn!(label, error = %error, "phrase broadcast failed");
            first_error = Some(error);
        }
    }

    match gossip_sender.broadcast_neighbors(payload).await {
        Ok(_) => {
            delivered = true;
        }
        Err(error) => {
            warn!(label, error = %error, "phrase neighbor broadcast failed");
            if first_error.is_none() {
                first_error = Some(error);
            }
        }
    }

    if delivered {
        Ok(())
    } else {
        Err(first_error.unwrap_or_else(|| anyhow::anyhow!("phrase message delivery failed")))
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

pub fn log_gossip_event(role: &str, event: &Event) {
    match event {
        Event::NeighborUp(peer) => {
            info!(role, peer = %peer, "neighbor joined topic");
        }
        Event::NeighborDown(peer) => {
            warn!(role, peer = %peer, "neighbor left topic");
        }
        Event::Received(message) => {
            info!(
                role,
                delivered_from = %message.delivered_from,
                scope = ?message.scope,
                bytes = message.content.len(),
                "received gossip message"
            );
        }
        Event::Lagged => {
            warn!(role, "gossip receiver lagged");
        }
    }
}

pub fn spawn_endpoint_watch_logger(endpoint: &Endpoint) {
    let endpoint = endpoint.clone();
    tokio::spawn(async move {
        use n0_watcher::Watcher;
        let endpoint_id = endpoint.addr().id;
        let mut stream = endpoint.watch_addr().stream();
        while let Some(addr) = stream.next().await {
            let relay = addr
                .relay_urls()
                .next()
                .cloned()
                .map(|u: iroh_96::RelayUrl| u.to_string());
            let direct_addrs: Vec<_> = addr.ip_addrs().copied().collect();
            info!(
                endpoint_id = %endpoint_id,
                relay = ?relay,
                direct_addrs = ?direct_addrs,
                "endpoint address update"
            );
        }
    });
}

pub fn spawn_endpoint_online_logger(endpoint: &Endpoint) {
    let endpoint = endpoint.clone();
    tokio::spawn(async move {
        let endpoint_id = endpoint.addr().id;
        match tokio::time::timeout(std::time::Duration::from_secs(10), endpoint.online()).await {
            Ok(_) => info!(endpoint_id = %endpoint_id, "endpoint reported online"),
            Err(_) => warn!(
                endpoint_id = %endpoint_id,
                "endpoint did not report online within 10s; relay or WAN connectivity may be unavailable"
            ),
        }
    });
}
