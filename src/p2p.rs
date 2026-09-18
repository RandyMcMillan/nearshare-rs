use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use aes_gcm::{Aes256Gcm, Nonce, aead::Aead};
use libp2p::{
    identity::Keypair,
    mdns, noise, request_response, tcp, yamux,
    swarm::{NetworkBehaviour, Swarm, SwarmEvent, Config as SwarmConfig},
    PeerId, StreamProtocol, Transport,
};
use libp2p::request_response::ProtocolSupport;
use rand::Rng;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot, RwLock};
use tokio::io::AsyncWriteExt;
use futures_util::StreamExt;

pub const CHUNK_SIZE: usize = 256 * 1024; // 256KB chunks
pub const PROTOCOL: &str = "/nearshare/1.0.0";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum NearShareRequest {
    Ping,
    SendFile {
        filename: String,
        chunk_index: u64,
        total_chunks: u64,
        data: Vec<u8>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum NearShareResponse {
    Pong {
        peer_id: String,
        name: String,
    },
    FileChunkAck {
        chunk_index: u64,
    },
    Error(String),
}

#[derive(Clone, Debug, Serialize)]
pub struct PeerInfo {
    pub peer_id: String,
    pub name: String,
    pub addresses: Vec<String>,
}

#[derive(NetworkBehaviour)]
pub struct NearShareBehaviour {
    pub mdns: mdns::tokio::Behaviour,
    pub rr: request_response::cbor::Behaviour<NearShareRequest, NearShareResponse>,
}

pub struct P2PHandle {
    pub local_peer_id: PeerId,
    pub name: String,
    peers: Arc<RwLock<HashMap<PeerId, PeerInfo>>>,
    cmd_tx: mpsc::Sender<P2PCommand>,
    cipher: Arc<Aes256Gcm>,
}

impl Clone for P2PHandle {
    fn clone(&self) -> Self {
        Self {
            local_peer_id: self.local_peer_id,
            name: self.name.clone(),
            peers: Arc::clone(&self.peers),
            cmd_tx: self.cmd_tx.clone(),
            cipher: Arc::clone(&self.cipher),
        }
    }
}

impl P2PHandle {
    pub async fn send_file(&self, peer_id: PeerId, filename: String) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(P2PCommand::SendFile {
                peer_id,
                filename,
                respond_to: tx,
            })
            .await?;
        rx.await?
    }

    pub async fn list_peers(&self) -> Vec<PeerInfo> {
        self.peers.read().await.values().cloned().collect()
    }

    pub async fn get_incoming_files(&self) -> Result<Vec<IncomingFile>> {
        let mut files = Vec::new();
        let incoming_dir = std::path::Path::new("uploads/incoming");
        if !incoming_dir.exists() {
            return Ok(files);
        }
        let mut peer_dirs = tokio::fs::read_dir(incoming_dir).await?;
        while let Some(peer_entry) = peer_dirs.next_entry().await? {
            let peer_dir = peer_entry.path();
            if !peer_dir.is_dir() {
                continue;
            }
            let peer_id = peer_dir.file_name().unwrap_or_default().to_string_lossy().to_string();
            let mut stack = vec![peer_dir.clone()];
            while let Some(dir) = stack.pop() {
                let mut entries = tokio::fs::read_dir(&dir).await?;
                while let Some(entry) = entries.next_entry().await? {
                    let path = entry.path();
                    if path.is_dir() {
                        stack.push(path);
                    } else {
                        let meta = entry.metadata().await?;
                        let rel = path.strip_prefix(&peer_dir).unwrap_or(&path);
                        files.push(IncomingFile {
                            from_peer: peer_id.clone(),
                            filename: rel.to_string_lossy().to_string(),
                            size: meta.len(),
                        });
                    }
                }
            }
        }
        files.sort_by(|a, b| a.filename.cmp(&b.filename));
        Ok(files)
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct IncomingFile {
    pub from_peer: String,
    pub filename: String,
    pub size: u64,
}

pub struct P2PNode {
    handle: P2PHandle,
    swarm: Swarm<NearShareBehaviour>,
    cmd_rx: mpsc::Receiver<P2PCommand>,
    pending_responses: HashMap<request_response::OutboundRequestId, oneshot::Sender<NearShareResponse>>,
    outgoing_transfers: HashMap<request_response::OutboundRequestId, OutgoingTransfer>,
    cipher: Arc<Aes256Gcm>,
}

struct OutgoingTransfer {
    peer_id: PeerId,
    filename: String,
    chunks: Vec<Vec<u8>>,
    next_chunk: usize,
    respond_to: oneshot::Sender<Result<()>>,
}

enum P2PCommand {
    SendFile {
        peer_id: PeerId,
        filename: String,
        respond_to: oneshot::Sender<Result<()>>,
    },
}

impl P2PNode {
    pub async fn new(name: String, cipher: Arc<Aes256Gcm>) -> Result<(Self, P2PHandle)> {
        let keypair = Keypair::generate_ed25519();
        let local_peer_id = PeerId::from(keypair.public());
        println!("[p2p] Local PeerId: {}", local_peer_id);

        let tcp = tcp::tokio::Transport::new(tcp::Config::default());
        let noise_config = noise::Config::new(&keypair)?;
        let transport = tcp
            .upgrade(libp2p::core::upgrade::Version::V1)
            .authenticate(noise_config)
            .multiplex(yamux::Config::default())
            .timeout(Duration::from_secs(20))
            .boxed();

        let mdns_config = mdns::Config {
            query_interval: Duration::from_secs(10),
            ..Default::default()
        };
        let mdns = mdns::tokio::Behaviour::new(mdns_config, local_peer_id)?;

        let rr = request_response::cbor::Behaviour::new(
            [(StreamProtocol::new(PROTOCOL), ProtocolSupport::Full)],
            request_response::Config::default(),
        );

        let behaviour = NearShareBehaviour { mdns, rr };

        let mut swarm = Swarm::new(
            transport,
            behaviour,
            local_peer_id,
            SwarmConfig::with_tokio_executor()
                .with_idle_connection_timeout(Duration::from_secs(300)),
        );

        swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;

        let peers = Arc::new(RwLock::new(HashMap::new()));
        let (cmd_tx, cmd_rx) = mpsc::channel(32);

        let handle = P2PHandle {
            local_peer_id,
            name: name.clone(),
            peers: Arc::clone(&peers),
            cmd_tx,
            cipher: Arc::clone(&cipher),
        };

        let node = P2PNode {
            handle: handle.clone(),
            swarm,
            cmd_rx,
            pending_responses: HashMap::new(),
            outgoing_transfers: HashMap::new(),
            cipher,
        };

        Ok((node, handle))
    }

    pub async fn run(mut self) {
        loop {
            tokio::select! {
                event = self.swarm.select_next_some() => {
                    self.handle_swarm_event(event).await;
                }
                cmd = self.cmd_rx.recv() => {
                    match cmd {
                        Some(cmd) => self.handle_command(cmd).await,
                        None => break,
                    }
                }
            }
        }
    }

    async fn handle_swarm_event(&mut self, event: SwarmEvent<NearShareBehaviourEvent>) {
        match event {
            SwarmEvent::Behaviour(NearShareBehaviourEvent::Mdns(mdns::Event::Discovered(list))) => {
                for (peer_id, addr) in list {
                    if peer_id == self.handle.local_peer_id {
                        continue;
                    }
                    println!("[p2p] Discovered peer: {} at {}", peer_id, addr);
                    self.swarm.add_peer_address(peer_id, addr.clone());
                    if let Err(e) = self.swarm.dial(peer_id) {
                        println!("[p2p] Dial to {} failed: {:?}", peer_id, e);
                    } else {
                        println!("[p2p] Dialing {} ...", peer_id);
                    }
                    let mut peers = self.handle.peers.write().await;
                    peers.insert(peer_id, PeerInfo {
                        peer_id: peer_id.to_string(),
                        name: format!("Peer {}", &peer_id.to_string()[..8]),
                        addresses: vec![addr.to_string()],
                    });
                }
            }
            SwarmEvent::Behaviour(NearShareBehaviourEvent::Mdns(mdns::Event::Expired(list))) => {
                for (peer_id, _addr) in list {
                    println!("[p2p] Peer expired: {}", peer_id);
                    let mut peers = self.handle.peers.write().await;
                    peers.remove(&peer_id);
                }
            }
            SwarmEvent::Behaviour(NearShareBehaviourEvent::Rr(request_response::Event::Message {
                peer,
                message,
            })) => {
                match message {
                    request_response::Message::Request {
                        request,
                        channel,
                        ..
                    } => {
                        self.handle_request(peer, request, channel).await;
                    }
                    request_response::Message::Response {
                        request_id,
                        response,
                        ..
                    } => {
                        self.handle_response(request_id, response).await;
                    }
                }
            }
            SwarmEvent::Behaviour(NearShareBehaviourEvent::Rr(
                request_response::Event::OutboundFailure {
                    request_id,
                    error,
                    ..
                },
            )) => {
                eprintln!("[p2p] Outbound failure for {}: {:?}", request_id, error);
                if let Some(transfer) = self.outgoing_transfers.remove(&request_id) {
                    let _ = transfer.respond_to.send(Err(anyhow::anyhow!("{:?}", error)));
                }
                if let Some(tx) = self.pending_responses.remove(&request_id) {
                    let _ = tx.send(NearShareResponse::Error(format!("{:?}", error)));
                }
            }
            SwarmEvent::Behaviour(NearShareBehaviourEvent::Rr(
                request_response::Event::InboundFailure { error, .. },
            )) => {
                eprintln!("[p2p] Inbound failure: {:?}", error);
            }
            SwarmEvent::NewListenAddr { address, .. } => {
                println!("[p2p] Listening on {}", address);
            }
            SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                println!("[p2p] Connected to {} via {}", peer_id, endpoint.get_remote_address());
            }
            SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                if let Some(c) = cause {
                    println!("[p2p] Disconnected from {}: {:?}", peer_id, c);
                } else {
                    println!("[p2p] Disconnected from {}", peer_id);
                }
            }
            SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                if let Some(pid) = peer_id {
                    println!("[p2p] Outgoing connection error to {}: {:?}", pid, error);
                }
            }
            _ => {}
        }
    }

    async fn handle_request(
        &mut self,
        peer: PeerId,
        request: NearShareRequest,
        channel: request_response::ResponseChannel<NearShareResponse>,
    ) {
        match request {
            NearShareRequest::Ping => {
                let response = NearShareResponse::Pong {
                    peer_id: self.handle.local_peer_id.to_string(),
                    name: self.handle.name.clone(),
                };
                let _ = self.swarm.behaviour_mut().rr.send_response(channel, response);
            }
            NearShareRequest::SendFile {
                filename,
                chunk_index,
                total_chunks,
                data,
            } => {
                let temp_dir = format!("uploads/incoming/.tmp/{}", peer);
                if let Err(e) = tokio::fs::create_dir_all(&temp_dir).await {
                    eprintln!("[p2p] Failed to create temp dir: {}", e);
                    let _ = self.swarm.behaviour_mut().rr.send_response(
                        channel,
                        NearShareResponse::Error(format!("Dir creation failed: {}", e)),
                    );
                    return;
                }
                let temp_path = format!("{}/{}", temp_dir, filename);
                let result = async {
                    if chunk_index == 0 {
                        if let Some(parent) = std::path::Path::new(&temp_path).parent() {
                            tokio::fs::create_dir_all(parent).await?;
                        }
                    }
                    let mut file = if chunk_index == 0 {
                        tokio::fs::File::create(&temp_path).await?
                    } else {
                        tokio::fs::OpenOptions::new()
                            .append(true)
                            .open(&temp_path)
                            .await?
                    };
                    file.write_all(&data).await?;
                    file.flush().await?;
                    Ok::<(), std::io::Error>(())
                }
                .await;

                if let Err(e) = result {
                    eprintln!("[p2p] Failed to write chunk: {}", e);
                    let _ = self.swarm.behaviour_mut().rr.send_response(
                        channel,
                        NearShareResponse::Error(format!("Write failed: {}", e)),
                    );
                    return;
                }

                println!(
                    "[p2p] Received chunk {}/{} of {} from {}",
                    chunk_index + 1,
                    total_chunks,
                    filename,
                    peer
                );

                // If last chunk, encrypt the assembled file with our local key
                if chunk_index + 1 == total_chunks {
                    let encrypt_result = async {
                        let plaintext = tokio::fs::read(&temp_path).await?;
                        let nonce_bytes = rand::thread_rng().r#gen::<[u8; 12]>();
                        #[allow(deprecated)]
                        let nonce = Nonce::from_slice(&nonce_bytes);
                        let ciphertext = self.cipher.encrypt(nonce, plaintext.as_ref())
                            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{:?}", e)))?;
                        let mut encrypted = Vec::new();
                        encrypted.extend_from_slice(&nonce_bytes);
                        encrypted.extend_from_slice(&ciphertext);
                        let final_dir = format!("uploads/incoming/{}", peer);
                        let final_path = format!("{}/{}", final_dir, filename);
                        if let Some(parent) = std::path::Path::new(&final_path).parent() {
                            tokio::fs::create_dir_all(parent).await?;
                        }
                        tokio::fs::write(&final_path, &encrypted).await?;
                        tokio::fs::remove_file(&temp_path).await?;
                        Ok::<(), std::io::Error>(())
                    }.await;

                    if let Err(e) = encrypt_result {
                        eprintln!("[p2p] Failed to encrypt incoming file: {}", e);
                        let _ = self.swarm.behaviour_mut().rr.send_response(
                            channel,
                            NearShareResponse::Error(format!("Encrypt failed: {}", e)),
                        );
                        return;
                    }
                    println!("[p2p] Saved encrypted incoming file {} from {}", filename, peer);
                }

                let _ = self
                    .swarm
                    .behaviour_mut()
                    .rr
                    .send_response(channel, NearShareResponse::FileChunkAck { chunk_index });
            }
        }
    }

    async fn handle_response(
        &mut self,
        request_id: request_response::OutboundRequestId,
        response: NearShareResponse,
    ) {
        // First check if this is a pending response for a transfer task
        if let Some(tx) = self.pending_responses.remove(&request_id) {
            let _ = tx.send(response.clone());
        }

        // Then handle as part of an outgoing transfer
        if let Some(transfer) = self.outgoing_transfers.remove(&request_id) {
            match response {
                NearShareResponse::FileChunkAck { chunk_index } => {
                    if chunk_index as usize + 1 >= transfer.chunks.len() {
                        println!(
                            "[p2p] Finished sending {} to {}",
                            transfer.filename, transfer.peer_id
                        );
                        let _ = transfer.respond_to.send(Ok(()));
                    } else {
                        let next_chunk = chunk_index as usize + 1;
                        let data = transfer.chunks[next_chunk].clone();
                        let req = NearShareRequest::SendFile {
                            filename: transfer.filename.clone(),
                            chunk_index: next_chunk as u64,
                            total_chunks: transfer.chunks.len() as u64,
                            data,
                        };
                        let new_req_id = self
                            .swarm
                            .behaviour_mut()
                            .rr
                            .send_request(&transfer.peer_id, req);
                        let mut transfer = transfer;
                        transfer.next_chunk = next_chunk;
                        self.outgoing_transfers.insert(new_req_id, transfer);
                    }
                }
                NearShareResponse::Error(e) => {
                    eprintln!("[p2p] Transfer error: {}", e);
                    let _ = transfer.respond_to.send(Err(anyhow::anyhow!("{}", e)));
                }
                _ => {
                    let _ = transfer.respond_to.send(Err(anyhow::anyhow!("Unexpected response")));
                }
            }
        }
    }

    async fn handle_command(&mut self, cmd: P2PCommand) {
        match cmd {
            P2PCommand::SendFile {
                peer_id,
                filename,
                respond_to,
            } => {
                let file_path = format!("uploads/{}", filename);
                let encrypted_data = match tokio::fs::read(&file_path).await {
                    Ok(d) => d,
                    Err(e) => {
                        let _ = respond_to.send(Err(anyhow::anyhow!("Read failed: {}", e)));
                        return;
                    }
                };

                if encrypted_data.len() < 12 {
                    let _ = respond_to.send(Err(anyhow::anyhow!("File too short")));
                    return;
                }
                let (nonce_bytes, ciphertext) = encrypted_data.split_at(12);
                #[allow(deprecated)]
                let nonce = Nonce::from_slice(nonce_bytes);
                let plaintext = match self.cipher.decrypt(nonce, ciphertext) {
                    Ok(p) => p,
                    Err(e) => {
                        let _ = respond_to.send(Err(anyhow::anyhow!("Decryption failed: {:?}", e)));
                        return;
                    }
                };

                let chunks: Vec<Vec<u8>> = plaintext.chunks(CHUNK_SIZE).map(|c| c.to_vec()).collect();
                if chunks.is_empty() {
                    let _ = respond_to.send(Ok(()));
                    return;
                }

                let req = NearShareRequest::SendFile {
                    filename: filename.clone(),
                    chunk_index: 0,
                    total_chunks: chunks.len() as u64,
                    data: chunks[0].clone(),
                };

                let req_id = self.swarm.behaviour_mut().rr.send_request(&peer_id, req);
                self.outgoing_transfers.insert(
                    req_id,
                    OutgoingTransfer {
                        peer_id,
                        filename,
                        chunks,
                        next_chunk: 0,
                        respond_to,
                    },
                );
            }
        }
    }
}
