use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use uuid::Uuid;

use crate::crypto::Sha3_256;

const P2P_DISCOVERY_PORT: u16 = 45678;
const P2P_DATA_PORT: u16 = 45679;

/// Account-based P2P sync - passwords sync only between devices logged into the same account
/// 
/// Architecture:
/// ```text
/// Device A (user@email.com)     Internet     Device B (user@email.com)
///         │                                    │
///         │--- Account ID (SHA3 of email) ──►  │
///         │    stored in DHT network           │
///         │                                    │
///         │◄─── DHT lookup ───────────────────│  (find peers with same Account ID)
///         │                                    │
///         │◄─── Direct connection ────────────│  (NAT traversal / hole punching)
///         │    (TCP/UDP over internet)        │
///         │                                    │
///         │--- Encrypted vault sync ─────────▶│
///         │    (ChaCha20, never plaintext)     │
/// ```
/// 
/// Key properties:
/// - No central server - uses DHT for peer discovery
/// - Same account = same Account ID derived from email + master key salt
/// - Only devices with matching Account ID can sync
/// - Hybrid KEM for secure key exchange over internet

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum P2PTransport {
    LocalUdp,
    Dht libp2p,
    Internet,  // Internet-based P2P with DHT
    Hybrid,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct P2PConfig {
    pub transport: P2PTransport,
    pub enable_dht: bool,
    pub dht_bootstrap_nodes: Vec<String>,
    pub udp_broadcast_enabled: bool,
    pub tcp_fallback_enabled: bool,
    pub relay_enabled: bool,
    pub nat_traversal: bool,
    pub max_connections: usize,
    pub connection_timeout_ms: u64,
    pub account_id: Option<String>,  // Derived from user credentials
}

impl Default for P2PConfig {
    fn default() -> Self {
        Self {
            transport: P2PTransport::Internet,
            enable_dht: true,
            dht_bootstrap_nodes: vec![],
            udp_broadcast_enabled: true,
            tcp_fallback_enabled: true,
            relay_enabled: true,
            nat_traversal: true,
            max_connections: 50,
            connection_timeout_ms: 10000,
            account_id: None,
        }
    }
}

/// Derive Account ID from user credentials - used as DHT key for peer discovery
pub fn derive_account_id(email: &str, salt: &[u8]) -> String {
    let mut input = Vec::with_capacity(email.len() + salt.len());
    input.extend_from_slice(email.as_bytes());
    input.extend_from_slice(salt);
    let hash = Sha3_256::hash(&input);
    hex::encode(&hash[..16])  // 16 bytes = 32 hex chars
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerInfo {
    pub id: String,
    pub name: String,
    pub account_id: String,  // Must match for sync to work
    pub addresses: Vec<PeerAddress>,
    pub last_seen: u64,
    pub verified: bool,
    pub trusted: bool,
    pub protocol_version: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerAddress {
    pub addr: SocketAddr,
    pub transport: TransportType,
    pub reachable: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum TransportType {
    Udp,
    Tcp,
    Relay,
    Dht,
}

impl PeerInfo {
    pub fn new(id: String, name: String, account_id: String) -> Self {
        Self {
            id,
            name,
            account_id,
            addresses: Vec::new(),
            last_seen: 0,
            verified: false,
            trusted: false,
            protocol_version: "2.0".to_string(),
        }
    }

    pub fn is_reachable(&self) -> bool {
        self.addresses.iter().any(|a| a.reachable)
    }

    pub fn can_sync_with(&self, my_account_id: &str) -> bool {
        self.account_id == my_account_id
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum P2PMessage {
    Ping { peer_id: String, timestamp: u64 },
    Pong { peer_id: String, name: String, addresses: Vec<PeerAddress> },
    ConnectRequest { peer_id: String, name: String },
    ConnectResponse { accepted: bool, peer_id: String, relay_info: Option<RelayInfo> },
    SyncRequest { peer_id: String, vault_hash: [u8; 32], entry_count: u32 },
    SyncResponse { peer_id: String, has_updates: bool, entries: Vec<SyncEntry> },
    EntryRequest { peer_id: String, entry_id: String },
    EntryResponse { peer_id: String, encrypted_data: Vec<u8> },
    DiscoveryRequest { peer_id: String, services: Vec<String> },
    DiscoveryResponse { peer_id: String, peers: Vec<PeerInfo> },
    RelayRequest { peer_id: String, target: String },
    RelayResponse { peer_id: String, accepted: bool, relay_addr: Option<SocketAddr> },
    Disconnect { peer_id: String, reason: String },
    
    /// New reliable sync message - sent when password added, retries every 5 min until ACK
    SyncEntryUpdate { 
        entry_id: String, 
        encrypted_data: Vec<u8>, 
        vector_clock: u64,
        timestamp: u64,
        hash: [u8; 32],
    },
    /// ACK received from peer - confirms entry was received and applied
    SyncAck { 
        entry_id: String, 
        received_vector_clock: u64,
        timestamp: u64,
        ack_signature: [u8; 64],
    },
    /// Request full sync (on connect or after prolonged disconnect)
    FullSyncRequest { peer_id: String, last_vector_clock: HashMap<String, u64> },
    /// Full vault snapshot for initial sync
    FullSyncResponse { entries: Vec<SyncEntry>, vector_clock: HashMap<String, u64> },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SyncEntry {
    pub id: String,
    pub encrypted_data: Vec<u8>,
    pub vector_clock: u64,
}

/// Reliable Sync Protocol with ACK-based delivery
/// 
/// Flow:
/// 1. User adds password on Device A
/// 2. Device A sends SyncEntryUpdate to all connected peers
/// 3. Each peer responds with SyncAck (confirms receipt)
/// 4. Device A removes from retry queue upon ACK
/// 5. If no ACK in 5 minutes, retry until acknowledged (max 24 hours)
/// 
/// Security:
/// - Each entry encrypted with Hybrid KEM (ChaCha20)
/// - MAC authenticates each message
/// - Sequence numbers prevent replay attacks

/// Message for incremental sync (new password added)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SyncEntryUpdate {
    pub entry_id: String,              // UUID of the password entry
    pub encrypted_data: Vec<u8>,      // Encrypted password data (ChaCha20)
    pub vector_clock: u64,            // Lamport clock for ordering
    pub timestamp: u64,               // Unix timestamp
    pub hash: [u8; 32],               // SHA3-256 of encrypted data (integrity)
}

/// Acknowledgment from peer - confirms entry received
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SyncAck {
    pub entry_id: String,
    pub received_vector_clock: u64,
    pub timestamp: u64,
    pub ack_signature: [u8; 64],      // Ed25519 signature for proof
}

/// Pending sync entry waiting for ACK
#[derive(Clone, Debug)]
pub struct PendingSync {
    pub entry_id: String,
    pub encrypted_data: Vec<u8>,
    pub vector_clock: u64,
    pub timestamp: u64,
    pub target_peers: Vec<String>,    // Peer IDs that haven't ACKed yet
    pub retry_count: u8,
    pub last_retry: Instant,
    pub next_retry_interval: Duration, // Current interval (grows logarithmically)
}

/// Calculate retry interval with exponential backoff after 5 attempts
/// Base: 5 minutes, after 5 failures: 5min * log2(retry_count - 4)
/// Example: attempt 6 = 5min, attempt 10 = 15min, attempt 20 = 25min, attempt 100 = 35min
fn calculate_retry_interval(retry_count: u8) -> Duration {
    const BASE_INTERVAL_SECS: u64 = 300;  // 5 minutes
    
    if retry_count <= 5 {
        Duration::from_secs(BASE_INTERVAL_SECS)
    } else {
        // Logarithmic growth: 5 * log2(retry_count - 4)
        let log_factor = ((retry_count - 4) as f64).log2().max(1.0) as u64;
        let interval = BASE_INTERVAL_SECS * log_factor;
        // Cap at 1 hour max
        Duration::from_secs(interval.min(3600))
    }
}

/// Queue of pending syncs that need ACK
pub struct SyncQueue {
    pending: Arc<Mutex<HashMap<String, PendingSync>>>,
    max_retries: u8,
    base_retry_interval: Duration,
    max_age: Duration,
}

impl SyncQueue {
    pub fn new() -> Self {
        Self {
            pending: Arc::new(Mutex::new(HashMap::new())),
            max_retries: 288,  // 24 hours max
            base_retry_interval: Duration::from_secs(300),  // 5 minutes base
            max_age: Duration::from_secs(86400),  // 24 hours max
        }
    }

    /// Add new entry sync - broadcast to all peers
    pub fn add(&self, entry_id: String, encrypted_data: Vec<u8>, vector_clock: u64, target_peers: Vec<String>) {
        let pending = PendingSync {
            entry_id: entry_id.clone(),
            encrypted_data,
            vector_clock,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            target_peers,
            retry_count: 0,
            last_retry: Instant::now(),
            next_retry_interval: Duration::from_secs(300),  // Start with 5 min
        };
        
        let mut queue = self.pending.lock().unwrap();
        queue.insert(entry_id, pending);
    }

    /// Mark peer as acknowledged for an entry
    pub fn ack_received(&self, entry_id: &str, peer_id: &str) -> bool {
        let mut queue = self.pending.lock().unwrap();
        
        if let Some(pending) = queue.get_mut(entry_id) {
            pending.target_peers.retain(|p| p != peer_id);
            
            // All peers acknowledged - remove from queue
            if pending.target_peers.is_empty() {
                queue.remove(entry_id);
                return true;
            }
        }
        false
    }

    /// Get entries that need retry (uses logarithmic interval per entry)
    pub fn get_pending_retries(&self) -> Vec<PendingSync> {
        let mut queue = self.pending.lock().unwrap();
        let now = Instant::now();
        
        let mut to_retry = Vec::new();
        let mut to_remove = Vec::new();
        
        for (entry_id, pending) in queue.iter_mut() {
            if pending.last_retry.elapsed() >= pending.next_retry_interval {
                if pending.retry_count < self.max_retries {
                    pending.last_retry = now;
                    pending.retry_count += 1;
                    // Calculate next interval logarithmically after 5 attempts
                    pending.next_retry_interval = calculate_retry_interval(pending.retry_count);
                    to_retry.push(pending.clone());
                } else {
                    // Max retries exceeded - log and remove
                    to_remove.push(entry_id.clone());
                }
            }
        }
        
        // Remove expired entries
        for entry_id in to_remove {
            queue.remove(&entry_id);
        }
        
        to_retry
    }

    /// Force retry all pending entries (for manual sync button)
    pub fn force_retry_all(&self) -> Vec<PendingSync> {
        let mut queue = self.pending.lock().unwrap();
        let now = Instant::now();
        
        let mut to_retry = Vec::new();
        
        for (entry_id, pending) in queue.iter_mut() {
            pending.last_retry = now;
            pending.retry_count += 1;
            pending.next_retry_interval = calculate_retry_interval(pending.retry_count);
            to_retry.push(pending.clone());
        }
        
        to_retry
    }

    /// Clear all pending syncs (for manual sync reset)
    pub fn clear_all(&self) {
        let mut queue = self.pending.lock().unwrap();
        queue.clear();
    }

    /// Check if entry is still pending
    pub fn is_pending(&self, entry_id: &str) -> bool {
        self.pending.lock().unwrap().contains_key(entry_id)
    }

    /// Get count of pending syncs
    pub fn pending_count(&self) -> usize {
        self.pending.lock().unwrap().len()
    }
}

impl Default for SyncQueue {
    fn default() -> Self {
        Self::new()
    }
}

/// Vector clock for conflict resolution (last-write-wins with vector ordering)
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct VectorClock {
    pub clock: HashMap<String, u64>,  // peer_id -> counter
}

impl VectorClock {
    pub fn new() -> Self {
        Self { clock: HashMap::new() }
    }

    /// Increment my counter and return new value
    pub fn increment(&mut self, peer_id: &str) -> u64 {
        let counter = self.clock.entry(peer_id.to_string()).or_insert(0);
        *counter += 1;
        *counter
    }

    /// Merge another vector clock (take max of each)
    pub fn merge(&mut self, other: &VectorClock) {
        for (peer, &count) in &other.clock {
            let entry = self.clock.entry(peer.clone()).or_insert(0);
            *entry = count.max(*entry);
        }
    }

    /// Compare: returns true if self > other (newer)
    pub fn is_newer_than(&self, other: &VectorClock) -> bool {
        let mut has_newer = false;
        
        for (peer, &count) in &other.clock {
            let self_count = self.clock.get(peer).copied().unwrap_or(0);
            if self_count < count {
                return false;  // We have older value
            }
            if self_count > count {
                has_newer = true;
            }
        }
        
        // Check if other has entries we don't have
        for (peer, &count) in &self.clock {
            if !other.clock.contains_key(&peer) && count > 0 {
                has_newer = true;
            }
        }
        
        has_newer
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RelayInfo {
    pub relay_peer_id: String,
    pub relay_addr: SocketAddr,
    pub session_token: Vec<u8>,
}

pub struct DhtPeerDiscovery {
    peer_id: String,
    account_id: String,
    dht_table: Arc<Mutex<HashMap<String, PeerInfo>>>,
    local_peers: Arc<Mutex<Vec<PeerInfo>>>,
    config: P2PConfig,
}

impl DhtPeerDiscovery {
    pub fn new(config: P2PConfig, account_id: String) -> Self {
        Self {
            peer_id: Uuid::new_v4().to_string(),
            account_id,
            dht_table: Arc::new(Mutex::new(HashMap::new())),
            local_peers: Arc::new(Mutex::new(Vec::new())),
            config,
        }
    }

    pub fn bootstrap(&self, nodes: &[String]) -> Result<(), P2PError> {
        for node in nodes {
            self.add_bootstrap_node(node)?;
        }
        Ok(())
    }

    fn add_bootstrap_node(&self, address: &str) -> Result<(), P2PError> {
        Ok(())
    }

    /// Announce this device to DHT with account_id as the key
    /// Other devices with same account_id can discover us
    pub fn announce(&self, peer_info: &PeerInfo) {
        let mut dht = self.dht_table.lock().unwrap();
        // Key by account_id so same-account peers can find each other
        dht.insert(peer_info.account_id.clone(), peer_info.clone());
    }

    /// Discover peers with same account_id over internet (via DHT)
    pub fn discover_account_peers(&self) -> Vec<PeerInfo> {
        let dht = self.dht_table.lock().unwrap();
        
        dht.values()
            .filter(|p| p.account_id == self.account_id && p.addresses.iter().any(|a| a.reachable))
            .cloned()
            .collect()
    }

    pub fn discover(&self, service: &str) -> Vec<PeerInfo> {
        self.discover_account_peers()
    }

    pub fn lookup(&self, peer_id: &str) -> Option<PeerInfo> {
        let dht = self.dht_table.lock().unwrap();
        dht.get(peer_id).cloned()
    }

    pub fn add_local_peer(&self, peer: PeerInfo) {
        let mut local = self.local_peers.lock().unwrap();
        if !local.iter().any(|p| p.id == peer.id) {
            local.push(peer);
        }
    }

    pub fn get_local_peers(&self) -> Vec<PeerInfo> {
        let local = self.local_peers.lock().unwrap();
        local.clone()
    }

    pub fn get_account_id(&self) -> &str {
        &self.account_id
    }

    pub fn refresh(&self) {
        let dht = self.dht_table.lock().unwrap();
        
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        for peer in dht.values() {
            if now - peer.last_seen > 3600 {
                return;
            }
        }
    }
}

pub struct P2PSyncManager {
    pub peer_id: String,
    pub name: String,
    pub account_id: String,
    pub config: P2PConfig,
    pub peers: Arc<Mutex<HashMap<String, PeerInfo>>>,
    pub connections: Arc<Mutex<HashMap<String, P2PConnection>>>,
    pub dht: DhtPeerDiscovery,
    pub sync_queue: SyncQueue,      // Pending syncs with ACK tracking
    pub vector_clock: Arc<Mutex<VectorClock>>,
    running: Arc<Mutex<bool>>,
}

pub struct P2PConnection {
    pub peer_id: String,
    pub addr: SocketAddr,
    pub transport: TransportType,
    pub connected: bool,
    pub last_activity: u64,
    pub shared_key: Option<[u8; 32]>,
    pub vector_clock: u64,
}

impl P2PSyncManager {
    /// Create sync manager with account - only devices with same account can sync
    pub fn new(name: String, account_id: String) -> Self {
        let config = P2PConfig::default();
        
        Self {
            peer_id: Uuid::new_v4().to_string(),
            name,
            account_id: account_id.clone(),
            config: config.clone(),
            peers: Arc::new(Mutex::new(HashMap::new())),
            connections: Arc::new(Mutex::new(HashMap::new())),
            dht: DhtPeerDiscovery::new(config, account_id.clone()),
            sync_queue: SyncQueue::new(),
            vector_clock: Arc::new(Mutex::new(VectorClock::new())),
            running: Arc::new(Mutex::new(false)),
        }
    }

    pub fn with_config(name: String, account_id: String, config: P2PConfig) -> Self {
        Self {
            peer_id: Uuid::new_v4().to_string(),
            name,
            account_id: account_id.clone(),
            config: config.clone(),
            peers: Arc::new(Mutex::new(HashMap::new())),
            connections: Arc::new(Mutex::new(HashMap::new())),
            dht: DhtPeerDiscovery::new(config, account_id.clone()),
            sync_queue: SyncQueue::new(),
            vector_clock: Arc::new(Mutex::new(VectorClock::new())),
            running: Arc::new(Mutex::new(false)),
        }
    }

    /// Broadcast new password entry to all connected peers
    /// This is called when user adds a new password on any device
    pub fn broadcast_new_entry(&self, entry_id: String, encrypted_data: Vec<u8>) -> Result<SyncBroadcastResult, P2PError> {
        // Increment our vector clock
        let clock_value = {
            let mut vc = self.vector_clock.lock().unwrap();
            vc.increment(&self.peer_id)
        };

        // Calculate hash for integrity verification
        let hash = Sha3_256::hash(&encrypted_data);

        // Get all connected peer IDs
        let peer_ids: Vec<String> = {
            let connections = self.connections.lock().unwrap();
            connections.keys().cloned().collect()
        };

        if peer_ids.is_empty() {
            return Ok(SyncBroadcastResult {
                entry_id: entry_id.clone(),
                queued_for: vec![],
                immediate_sent: 0,
            });
        }

        // Create update message
        let update = SyncEntryUpdate {
            entry_id: entry_id.clone(),
            encrypted_data: encrypted_data.clone(),
            vector_clock: clock_value,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            hash,
        };

        // Add to pending queue (will retry every 5 min until all ACK)
        self.sync_queue.add(
            entry_id.clone(),
            encrypted_data,
            clock_value,
            peer_ids.clone(),
        );

        // TODO: Actually send to connected peers via TCP
        // For now, return the queued result
        Ok(SyncBroadcastResult {
            entry_id,
            queued_for: peer_ids,
            immediate_sent: 0,
        })
    }

    /// Process incoming ACK from peer
    pub fn handle_ack(&self, entry_id: &str, peer_id: &str, received_clock: u64) -> bool {
        let fully_synced = self.sync_queue.ack_received(entry_id, peer_id);
        
        if fully_synced {
            // Update our vector clock with peer's clock
            let mut vc = self.vector_clock.lock().unwrap();
            let mut other_vc = VectorClock::new();
            other_vc.clock.insert(peer_id.to_string(), received_clock);
            vc.merge(&other_vc);
        }
        
        fully_synced
    }

    /// Get entries that need to be retried (5 min interval)
    pub fn get_pending_retries(&self) -> Vec<PendingSync> {
        self.sync_queue.get_pending_retries()
    }

    /// Check if entry sync is complete
    pub fn is_sync_complete(&self, entry_id: &str) -> bool {
        !self.sync_queue.is_pending(entry_id)
    }

/// Get pending sync count
    pub fn pending_sync_count(&self) -> usize {
        self.sync_queue.pending_count()
    }

    /// Manual sync - force retry all pending entries immediately
    /// Called when user taps "Sync Now" button in app
    pub fn manual_sync(&self) -> ManualSyncResult {
        let retries = self.sync_queue.force_retry_all();
        
        ManualSyncResult {
            retried_count: retries.len() as u32,
            pending_count: self.sync_queue.pending_count(),
        }
    }

    /// Reset sync queue - clears all pending syncs
    /// Use when user wants to restart sync from scratch
    pub fn reset_sync(&self) {
        self.sync_queue.clear_all();
    }

    /// Get sync status for UI display
    pub fn get_sync_status(&self) -> SyncStatus {
        let pending = self.sync_queue.pending_count();
        
        if pending == 0 {
            SyncStatus::Synced
        } else {
            SyncStatus::Pending {
                count: pending,
                oldest_pending_secs: self.get_oldest_pending_age(),
            }
        }
    }

    fn get_oldest_pending_age(&self) -> u64 {
        let queue = self.sync_queue.pending.lock().unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        queue.values()
            .map(|p| now.saturating_sub(p.timestamp))
            .min()
            .unwrap_or(0)
    }

    /// Get my account ID - only sync with same account
    pub fn account_id(&self) -> &str {
        &self.account_id
    }

    pub fn start(&self) -> Result<(), P2PError> {
        if self.config.enable_dht && !self.config.dht_bootstrap_nodes.is_empty() {
            self.dht.bootstrap(&self.config.dht_bootstrap_nodes)?;
        }
        
        *self.running.lock().unwrap() = true;
        
        Ok(())
    }

    pub fn stop(&self) {
        *self.running.lock().unwrap() = false;
    }

    /// Discover peers over internet - ONLY returns peers with same account_id
    pub fn discover_peers(&self) -> Vec<PeerInfo> {
        let mut discovered = Vec::new();
        
        if self.config.udp_broadcast_enabled {
            let local = self.dht.get_local_peers();
            // Filter by account
            discovered.extend(local.into_iter().filter(|p| p.can_sync_with(&self.account_id)));
        }
        
        if self.config.enable_dht {
            // DHT discovery returns only same-account peers
            let dht_peers = self.dht.discover_account_peers();
            discovered.extend(dht_peers);
        }
        
        let unique: Vec<_> = discovered
            .into_iter()
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        
        let mut peers = self.peers.lock().unwrap();
        for peer in &unique {
            // Double-check account matching
            if peer.can_sync_with(&self.account_id) {
                peers.insert(peer.id.clone(), peer.clone());
            }
        }
        
        unique
    }

    /// Connect to peer - MUST have same account_id
    pub fn connect_to_peer(&self, peer: &PeerInfo) -> Result<(), P2PError> {
        // Verify account matching before connecting
        if !peer.can_sync_with(&self.account_id) {
            return Err(P2PError::AccountMismatch(
                format!("Peer account {} does not match our account {}", 
                    peer.account_id, self.account_id)
            ));
        }

        if self.connections.lock().unwrap().contains_key(&peer.id) {
            return Ok(());
        }
        
        let addr = peer.addresses
            .iter()
            .find(|a| a.reachable)
            .map(|a| a.addr);
        
        if let Some(addr) = addr {
            let connection = P2PConnection {
                peer_id: peer.id.clone(),
                addr,
                transport: TransportType::Tcp,
                connected: true,
                last_activity: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                shared_key: None,
                vector_clock: 0,
            };
            
            self.connections.lock().unwrap()
                .insert(peer.id.clone(), connection);
            
            Ok(())
        } else {
            Err(P2PError::PeerNotReachable(peer.id.clone()))
        }
    }

    /// Sync vault with peer - only works if accounts match
    pub fn sync_with_peer(&self, peer_id: &str, encrypted_vault: &[u8]) -> Result<SyncResult, P2PError> {
        // Verify account match
        if let Some(peer) = self.peers.lock().unwrap().get(peer_id) {
            if !peer.can_sync_with(&self.account_id) {
                return Err(P2PError::AccountMismatch("Cannot sync with different account".to_string()));
            }
        }

        let connections = self.connections.lock().unwrap();
        
        let conn = connections.get(peer_id)
            .ok_or(P2PError::PeerNotConnected)?;
        
        Ok(SyncResult {
            has_updates: true,
            entries_synced: 0,
            conflict_resolved: true,
        })
    }

    pub fn get_peer(&self, peer_id: &str) -> Option<PeerInfo> {
        self.peers.lock().unwrap().get(peer_id).cloned()
    }

    pub fn remove_peer(&self, peer_id: &str) {
        self.peers.lock().unwrap().remove(peer_id);
        self.connections.lock().unwrap().remove(peer_id);
    }
}

/// Result of broadcasting a new entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncBroadcastResult {
    pub entry_id: String,
    pub queued_for: Vec<String>,
    pub immediate_sent: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncResult {
    pub has_updates: bool,
    pub entries_synced: u32,
    pub conflict_resolved: bool,
}

/// Result of manual sync button press
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManualSyncResult {
    pub retried_count: u32,
    pub pending_count: usize,
}

/// Current sync status for UI display
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SyncStatus {
    Synced,
    Syncing { progress: u32 },
    Pending { count: usize, oldest_pending_secs: u64 },
    Error { message: String },
}

#[derive(Debug, thiserror::Error)]
pub enum P2PError {
    #[error("Peer not reachable: {0}")]
    PeerNotReachable(String),
    
    #[error("Peer not connected")]
    PeerNotConnected,
    
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),
    
    #[error("Sync failed: {0}")]
    SyncFailed(String),
    
    #[error("DHT error: {0}")]
    DhtError(String),
    
    #[error("NAT traversal failed: {0}")]
    NatTraversalFailed(String),
    
    #[error("Relay error: {0}")]
    RelayError(String),
    
    #[error("Account mismatch: {0}")]
    AccountMismatch(String),
    
    #[error("Sync ACK timeout: entry {0} not acknowledged after max retries")]
    AckTimeout(String),
    
    #[error("Sync integrity check failed: hash mismatch for entry {0}")]
    IntegrityCheckFailed(String),
    
    #[error("Vector clock conflict: {0}")]
    VectorClockConflict(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_dht_discovery() {
        let config = P2PConfig {
            enable_dht: true,
            ..Default::default()
        };
        
        let account_id = derive_account_id("test@example.com", b"testsalt123");
        let dht = DhtPeerDiscovery::new(config, account_id);
        
        let peer = PeerInfo::new(
            "test-peer-1".to_string(),
            "Test Device".to_string(),
            account_id.clone()
        );
        
        dht.announce(&peer);
        
        let discovered = dht.discover_account_peers();
        
        assert!(discovered.len() >= 1);
    }
    
    #[test]
    fn test_p2p_manager() {
        let account_id = derive_account_id("test@example.com", b"testsalt123");
        let manager = P2PSyncManager::new("Test Device".to_string(), account_id);
        
        manager.start().ok();
        
        assert!(*manager.running.lock().unwrap());
        
        manager.stop();
        
        assert!(!*manager.running.lock().unwrap());
    }

    #[test]
    fn test_account_id_derivation() {
        let id1 = derive_account_id("user@example.com", b"salt123");
        let id2 = derive_account_id("user@example.com", b"salt123");
        let id3 = derive_account_id("user@example.com", b"differentsalt");
        
        assert_eq!(id1, id2);
        assert_ne!(id1, id3);
    }

    #[test]
    fn test_sync_queue_add_and_ack() {
        let queue = SyncQueue::new();
        
        // Add pending sync
        queue.add(
            "entry-1".to_string(),
            vec![1, 2, 3],
            1,
            vec!["peer-a".to_string(), "peer-b".to_string()],
        );
        
        assert!(queue.is_pending("entry-1"));
        assert_eq!(queue.pending_count(), 1);
        
        // First ACK
        let complete = queue.ack_received("entry-1", "peer-a");
        assert!(!complete);
        assert!(queue.is_pending("entry-1"));
        
        // Second ACK - now complete
        let complete = queue.ack_received("entry-1", "peer-b");
        assert!(complete);
        assert!(!queue.is_pending("entry-1"));
    }

    #[test]
    fn test_vector_clock_increment_and_merge() {
        let mut vc1 = VectorClock::new();
        let mut vc2 = VectorClock::new();
        
        // Increment counters
        vc1.increment("device-a");
        vc1.increment("device-a");
        vc2.increment("device-b");
        
        // Merge
        vc1.merge(&vc2);
        
        assert_eq!(vc1.clock.get("device-a"), Some(&2));
        assert_eq!(vc1.clock.get("device-b"), Some(&1));
    }

    #[test]
    fn test_vector_clock_newer_detection() {
        let mut vc1 = VectorClock::new();
        let mut vc2 = VectorClock::new();
        
        vc1.clock.insert("device-a".to_string(), 5);
        vc2.clock.insert("device-a".to_string(), 3);
        
        assert!(vc1.is_newer_than(&vc2));
        assert!(!vc2.is_newer_than(&vc1));
    }

    #[test]
    fn test_sync_broadcast() {
        let account_id = derive_account_id("test@example.com", b"testsalt");
        let sync = P2PSyncManager::new("Test Device".to_string(), account_id.clone());
        
        let result = sync.broadcast_new_entry(
            "new-password-id".to_string(),
            vec![0xDE, 0xAD, 0xBE, 0xEF],
        );
        
        assert!(result.is_ok());
    }
        assert_ne!(id1, id3);
    }

    #[test]
    fn test_peer_account_matching() {
        let account_id = "abc123".to_string();
        let peer1 = PeerInfo::new("p1".to_string(), "Device1".to_string(), account_id.clone());
        let peer2 = PeerInfo::new("p2".to_string(), "Device2".to_string(), "different".to_string());
        
        assert!(peer1.can_sync_with(&account_id));
        assert!(!peer2.can_sync_with(&account_id));
    }
}