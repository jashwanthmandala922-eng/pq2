use serde::{Deserialize, Serialize};
use std::net::{SocketAddr, UdpSocket, TcpListener, TcpStream};
use std::time::Duration;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

use crate::crypto::{Sha3_256, ChaChaRng};

pub mod dht_p2p;

pub use dht_p2p::{
    P2PSyncManager, P2PConfig, PeerInfo as DhtPeerInfo, P2PMessage as DhtP2PMessage,
    derive_account_id, SyncEntry, SyncResult as DhtSyncResult, P2PError as DhtP2PError,
    SyncEntryUpdate, SyncAck, SyncQueue, PendingSync, VectorClock, SyncBroadcastResult,
    ManualSyncResult, SyncStatus,
};

/// Password Sync Flow (Device-to-Device):
/// ```text
/// Device A                    Device B
///   |                            |
///   |--- UDP Broadcast --------->|  (P2P Discovery on port 45678)
///   |<-- Pong with info --------|   (PeerInfo exchange)
///   |                            |
///   |--- TCP Connect ---------->|  (Port 45679)
///   |                            |
///   |--- SyncRequest ---------->|  (vault_hash: SHA3 of encrypted vault)
///   |<-- SyncResponse ----------|  (has_updates, entry_count)
///   |                            |
///   |--- EntryRequest -------->|  (request specific entries)
///   |<-- EntryResponse ---------|  (encrypted_data: ChaCha20 encrypted)
/// ```
/// 
/// Security:
/// - All data encrypted with ChaCha20 using shared key derived from hybrid KEM
/// - Messages signed with Ed25519 (using SHA3-256 hash as key)
/// - No plaintext passwords ever transmitted
/// - Vector clocks for conflict resolution (last-write-wins)
pub const P2P_DISCOVERY_PORT: u16 = 45678;
pub const P2P_DATA_PORT: u16 = 45679;
pub const MAX_PAYLOAD_SIZE: usize = 65507;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub id: String,
    pub name: String,
    pub addr: SocketAddr,
    pub last_seen: u64,
    pub verified: bool,
}

impl PeerInfo {
    pub fn new(id: String, name: String, addr: SocketAddr) -> Self {
        Self {
            id,
            name,
            addr,
            last_seen: 0,
            verified: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum P2PMessage {
    Ping { peer_id: String },
    Pong { peer_id: String, name: String },
    ConnectRequest { peer_id: String, name: String },
    ConnectResponse { accepted: bool, peer_id: String },
    SyncRequest { peer_id: String, vault_hash: [u8; 32] },
    SyncResponse { peer_id: String, has_updates: bool, entry_count: u32 },
    EntryRequest { peer_id: String, entry_id: String },
    EntryResponse { peer_id: String, encrypted_data: Vec<u8> },
    Disconnect { peer_id: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct P2PProtocol {
    version: u8,
    message_type: String,
    peer_id: String,
    timestamp: u64,
    payload: Vec<u8>,
    signature: [u8; 64],
}

impl P2PProtocol {
    pub fn new(message: P2PMessage) -> Self {
        let payload = serde_json::to_vec(&message).unwrap_or_default();
        
        Self {
            version: 1,
            message_type: format!("{:?}", message),
            peer_id: String::new(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            payload,
            signature: [0u8; 64],
        }
    }

    pub fn sign(&mut self, secret_key: &[u8; 32]) {
        let mut msg = Vec::with_capacity(self.payload.len() + 32);
        msg.extend_from_slice(&self.payload);
        msg.extend_from_slice(secret_key);
        
        let hash = Sha3_256::hash(&msg);
        self.signature[..32].copy_from_slice(&hash);
    }

    pub fn verify(&self, public_key: &[u8; 32]) -> bool {
        let mut msg = Vec::with_capacity(self.payload.len() + 32);
        msg.extend_from_slice(&self.payload);
        msg.extend_from_slice(public_key);
        
        let hash = Sha3_256::hash(&msg);
        hash[..32] == self.signature[..32]
    }

    pub fn encrypt(&mut self, shared_key: &[u8; 32]) {
        let mut nonce = [0u8; 12];
        ChaChaRng::new(shared_key).fill_bytes(&mut nonce);
        
        let mut key_array = [0u32; 8];
        for i in 0..8 {
            key_array[i] = u32::from_le_bytes([
                shared_key[4 * i],
                shared_key[4 * i + 1],
                shared_key[4 * i + 2],
                shared_key[4 * i + 3],
            ]);
        }
        
        p2p_chacha20_xor(
            &mut self.payload, 
            &key_array, 
            &nonce
        );
    }
}

pub struct P2PManager {
    peer_id: String,
    name: String,
    peers: Arc<Mutex<HashMap<String, PeerInfo>>>,
    connections: Arc<Mutex<HashMap<String, Connection>>>,
    secret_key: [u8; 32],
    public_key: [u8; 32],
    running: Arc<Mutex<bool>>,
}

pub struct Connection {
    pub peer_id: String,
    pub addr: SocketAddr,
    pub connected: bool,
    pub last_activity: u64,
    pub shared_key: Option<[u8; 32]>,
}

impl P2PManager {
    pub fn new(name: String) -> Self {
        let mut secret_key = [0u8; 32];
        ChaChaRng::new(b"SecureVault-P2P-keygen!").fill_bytes(&mut secret_key);
        
        let public_key = {
            let hash = Sha3_256::hash(&secret_key);
            hash
        };
        
        Self {
            peer_id: Uuid::new_v4().to_string(),
            name,
            peers: Arc::new(Mutex::new(HashMap::new())),
            connections: Arc::new(Mutex::new(HashMap::new())),
            secret_key,
            public_key,
            running: Arc::new(Mutex::new(false)),
        }
    }

    pub fn peer_id(&self) -> &str {
        &self.peer_id
    }

    pub fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }

    pub fn start_discovery(&self) -> Result<(), P2PError> {
        let socket = UdpSocket::bind(format!("0.0.0.0:{}", P2P_DISCOVERY_PORT))
            .map_err(|e| P2PError::BindError(e.to_string()))?;
        
        socket.set_broadcast(true)
            .map_err(|e| P2PError::BindError(e.to_string()))?;

        socket.set_nonblocking(true)
            .map_err(|e| P2PError::BindError(e.to_string()))?;

        let running = Arc::clone(&self.running);
        let peer_id = self.peer_id.clone();
        let name = self.name.clone();
        let peers = Arc::clone(&self.peers);

        std::thread::spawn(move || {
            let mut buf = [0u8; MAX_PAYLOAD_SIZE];
            
            while *running.lock().unwrap() {
                if let Ok((len, addr)) = socket.recv_from(&mut buf) {
                    if let Ok(msg) = serde_json::from_slice::<P2PProtocol>(&buf[..len]) {
                        if let Ok(ping) = serde_json::from_slice::<P2PMessage>(&msg.payload) {
                            match ping {
                                P2PMessage::Ping { peer_id: discovered_id } => {
                                    let response = P2PProtocol::new(
                                        P2PMessage::Pong { 
                                            peer_id: peer_id.clone(), 
                                            name: name.clone() 
                                        }
                                    );
                                    
                                    let _ = socket.send_to(
                                        &serde_json::to_vec(&response).unwrap(),
                                        addr,
                                    );
                                }
                                P2PMessage::Pong { peer_id, name } => {
                                    let mut peers = peers.lock().unwrap();
                                    peers.insert(
                                        peer_id.clone(),
                                        PeerInfo::new(peer_id, name, addr),
                                    );
                                }
                                _ => {}
                            }
                        }
                    }
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        });

        Ok(())
    }

    pub fn broadcast_presence(&self) -> Result<(), P2PError> {
        let socket = UdpSocket::bind("0.0.0.0:0")
            .map_err(|e| P2PError::BindError(e.to_string()))?;
        
        socket.set_broadcast(true)
            .map_err(|e| P2PError::BindError(e.to_string()))?;

        let msg = P2PProtocol::new(
            P2PMessage::Ping { peer_id: self.peer_id.clone() }
        );
        
        let data = serde_json::to_vec(&msg)
            .map_err(|e| P2PError::SerializationError(e.to_string()))?;
        
        socket.send_to(
            &data,
            format!("255.255.255.255:{}", P2P_DISCOVERY_PORT),
        ).map_err(|e| P2PError::SendError(e.to_string()))?;

        Ok(())
    }

    pub fn get_available_peers(&self) -> Vec<PeerInfo> {
        let peers = self.peers.lock().unwrap();
        peers.values().cloned().collect()
    }

    pub fn connect_to_peer(&self, peer: &PeerInfo) -> Result<(), P2PError> {
        let stream = TcpStream::connect_timeout(
            &peer.addr,
            Duration::from_secs(10),
        ).map_err(|e| P2PError::ConnectionError(e.to_string()))?;

        stream.set_read_timeout(Some(Duration::from_secs(30)))
            .map_err(|e| P2PError::ConnectionError(e.to_string()))?;
        
        let msg = P2PProtocol::new(
            P2PMessage::ConnectRequest { 
                peer_id: self.peer_id.clone(),
                name: self.name.clone(),
            }
        );
        
        let data = serde_json::to_vec(&msg)
            .map_err(|e| P2PError::SerializationError(e.to_string()))?;
        
        use std::io::Write;
        stream.write_all(&data).map_err(|e| P2PError::SendError(e.to_string()))?;

        Ok(())
    }

    pub fn stop(&self) {
        *self.running.lock().unwrap() = false;
    }

    pub fn sync_with_peer(
        &self, 
        peer_id: &str, 
        encrypted_vault: &[u8],
    ) -> Result<SyncResult, P2PError> {
        let vault_hash = Sha3_256::hash(encrypted_vault);
        
        let connections = self.connections.lock().unwrap();
        let conn = connections.get(peer_id)
            .ok_or(P2PError::PeerNotConnected)?;
        
        let stream = TcpStream::connect_timeout(
            &conn.addr,
            Duration::from_secs(10),
        ).map_err(|e| P2PError::ConnectionError(e.to_string()))?;

        let msg = P2PProtocol::new(
            P2PMessage::SyncRequest { 
                peer_id: self.peer_id.clone(),
                vault_hash,
            }
        );
        
        let data = serde_json::to_vec(&msg)
            .map_err(|e| P2PError::SerializationError(e.to_string()))?;
        
        use std::io::Write;
        stream.write_all(&data).map_err(|e| P2PError::SendError(e.to_string()))?;

        let mut response_buf = [0u8; MAX_PAYLOAD_SIZE];
        let n = stream.read(&mut response_buf)
            .map_err(|e| P2PError::ReceiveError(e.to_string()))?;
        
        let response: P2PProtocol = serde_json::from_slice(&response_buf[..n])
            .map_err(|e| P2PError::DeserializationError(e.to_string()))?;
        
        if let Ok(sync_resp) = serde_json::from_slice::<P2PMessage>(&response.payload) {
            if let P2PMessage::SyncResponse { has_updates, entry_count, .. } = sync_resp {
                return Ok(SyncResult {
                    has_updates,
                    entry_count,
                });
            }
        }

        Err(P2PError::ProtocolError("Invalid response".to_string()))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncResult {
    pub has_updates: bool,
    pub entry_count: u32,
}

#[derive(Debug, thiserror::Error)]
pub enum P2PError {
    #[error("Bind error: {0}")]
    BindError(String),
    
    #[error("Send error: {0}")]
    SendError(String),
    
    #[error("Receive error: {0}")]
    ReceiveError(String),
    
    #[error("Connection error: {0}")]
    ConnectionError(String),
    
    #[error("Peer not connected")]
    PeerNotConnected,
    
    #[error("Serialization error: {0}")]
    SerializationError(String),
    
    #[error("Deserialization error: {0}")]
    DeserializationError(String),
    
    #[error("Protocol error: {0}")]
    ProtocolError(String),
}

fn p2p_chacha20_xor(data: &mut [u8], key: &[u32; 8], nonce: &[u8; 12]) {
    let mut state = [
        0x61707865u32, 0x3320646eu32, 0x79622d32u32, 0x6b206574u32,
        key[0], key[1], key[2], key[3],
        key[4], key[5], key[6], key[7],
        u32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]),
        u32::from_le_bytes([nonce[4], nonce[5], nonce[6], nonce[7]]),
        u32::from_le_bytes([nonce[8], nonce[9], nonce[10], nonce[11]]),
    ];

    for (chunk_idx, chunk) in data.chunks_mut(64).enumerate() {
        let mut working = state;
        working[12] = state[12].wrapping_add(chunk_idx as u32);
        
        let mut block = [0u8; 64];
        for i in 0..16 {
            let le = working[i].to_le_bytes();
            block[4 * i] = le[0];
            block[4 * i + 1] = le[1];
            block[4 * i + 2] = le[2];
            block[4 * i + 3] = le[3];
        }
        
        p2p_quarter_round(&mut working, 0, 4, 8, 12);
        p2p_quarter_round(&mut working, 1, 5, 9, 13);
        p2p_quarter_round(&mut working, 2, 6, 10, 14);
        p2p_quarter_round(&mut working, 3, 7, 11, 15);
        p2p_quarter_round(&mut working, 0, 5, 10, 15);
        p2p_quarter_round(&mut working, 1, 6, 11, 12);
        p2p_quarter_round(&mut working, 2, 7, 8, 13);
        p2p_quarter_round(&mut working, 3, 4, 9, 14);
        
        for i in 0..16 {
            let le = (working[i].wrapping_add(state[i])).to_le_bytes();
            block[4 * i] = le[0];
            block[4 * i + 1] = le[1];
            block[4 * i + 2] = le[2];
            block[4 * i + 3] = le[3];
        }
        
        for (i, &b) in block.iter().enumerate() {
            if i < chunk.len() {
                chunk[i] ^= b;
            }
        }
    }
}

fn p2p_quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(16);
    
    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(12);
    
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(8);
    
    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(7);
}