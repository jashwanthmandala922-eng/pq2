use serde::{Deserialize, Serialize};
use tauri::State;
use std::sync::Mutex;

#[derive(Debug, Serialize, Deserialize)]
pub struct VaultEntry {
    pub id: String,
    pub title: String,
    pub username: Option<String>,
    pub password: String,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub created: u64,
    pub modified: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UnlockResult {
    pub success: bool,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PeerInfo {
    pub id: String,
    pub name: String,
    pub ip: String,
    pub connected: bool,
}

pub struct AppState {
    pub locked: Mutex<bool>,
    pub entries: Mutex<Vec<VaultEntry>>,
    pub master_key: Mutex<Option<Vec<u8>>>,
    pub peers: Mutex<Vec<PeerInfo>>,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            locked: Mutex::new(true),
            entries: Mutex::new(Vec::new()),
            master_key: Mutex::new(None),
            peers: Mutex::new(Vec::new()),
        }
    }
}

#[tauri::command]
pub fn create_vault(
    password: String,
    state: State<AppState>,
) -> Result<UnlockResult, String> {
    if password.len() < 8 {
        return Ok(UnlockResult {
            success: false,
            error: Some("Password must be at least 8 characters".to_string()),
        });
    }

    let mut locked = state.locked.lock().unwrap();
    *locked = false;

    Ok(UnlockResult {
        success: true,
        error: None,
    })
}

#[tauri::command]
pub fn unlock_vault(
    password: String,
    state: State<AppState>,
) -> Result<UnlockResult, String> {
    let master_key = derive_key(&password);
    
    let mut locked = state.locked.lock().unwrap();
    let mut key = state.master_key.lock().unwrap();
    
    *locked = false;
    *key = Some(master_key);

    Ok(UnlockResult {
        success: true,
        error: None,
    })
}

#[tauri::command]
pub fn lock_vault(state: State<AppState>) -> Result<(), String> {
    let mut locked = state.locked.lock().unwrap();
    let mut key = state.master_key.lock().unwrap();
    
    *locked = true;
    *key = None;
    
    Ok(())
}

#[tauri::command]
pub fn add_entry(
    title: String,
    username: Option<String>,
    password: String,
    url: Option<String>,
    notes: Option<String>,
    state: State<AppState>,
) -> Result<VaultEntry, String> {
    let locked = state.locked.lock().unwrap();
    if *locked {
        return Err("Vault is locked".to_string());
    }
    
    let entry = VaultEntry {
        id: uuid::Uuid::new_v4().to_string(),
        title,
        username,
        password,
        url,
        notes,
        created: current_time(),
        modified: current_time(),
    };
    
    let mut entries = state.entries.lock().unwrap();
    entries.push(entry.clone());
    
    Ok(entry)
}

#[tauri::command]
pub fn get_entries(state: State<AppState>) -> Result<Vec<VaultEntry>, String> {
    let locked = state.locked.lock().unwrap();
    if *locked {
        return Err("Vault is locked".to_string());
    }
    
    let entries = state.entries.lock().unwrap();
    Ok(entries.clone())
}

#[tauri::command]
pub fn update_entry(
    id: String,
    title: String,
    username: Option<String>,
    password: String,
    url: Option<String>,
    notes: Option<String>,
    state: State<AppState>,
) -> Result<VaultEntry, String> {
    let locked = state.locked.lock().unwrap();
    if *locked {
        return Err("Vault is locked".to_string());
    }
    
    let mut entries = state.entries.lock().unwrap();
    
    if let Some(entry) = entries.iter_mut().find(|e| e.id == id) {
        entry.title = title;
        entry.username = username;
        entry.password = password;
        entry.url = url;
        entry.notes = notes;
        entry.modified = current_time();
        Ok(entry.clone())
    } else {
        Err("Entry not found".to_string())
    }
}

#[tauri::command]
pub fn delete_entry(
    id: String,
    state: State<AppState>,
) -> Result<(), String> {
    let locked = state.locked.lock().unwrap();
    if *locked {
        return Err("Vault is locked".to_string());
    }
    
    let mut entries = state.entries.lock().unwrap();
    entries.retain(|e| e.id != id);
    
    Ok(())
}

#[tauri::command]
pub fn sync_start_discovery(state: State<AppState>) -> Result<(), String> {
    let mut peers = state.peers.lock().unwrap();
    peers.push(PeerInfo {
        id: "demo-peer".to_string(),
        name: "Demo Device".to_string(),
        ip: "192.168.1.100".to_string(),
        connected: true,
    });
    Ok(())
}

#[tauri::command]
pub fn sync_get_peers(state: State<AppState>) -> Result<Vec<PeerInfo>, String> {
    let peers = state.peers.lock().unwrap();
    Ok(peers.clone())
}

#[tauri::command]
pub fn sync_connect_peer(
    peer_id: String,
    state: State<AppState>,
) -> Result<(), String> {
    Ok(())
}

#[tauri::command]
pub fn sync_force_retry(state: State<AppState>) -> Result<u32, String> {
    let entries = state.entries.lock().unwrap();
    Ok(entries.len() as u32)
}

#[tauri::command]
pub fn generate_password(
    length: u32,
    include_special: bool,
) -> Result<String, String> {
    let charset = if include_special {
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?"
    } else {
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    };
    
    let mut rng = ChaChaRng::new(b"SecureVault-password!");
    let mut password = String::new();
    
    for _ in 0..length {
        let idx = (rng.next_u32() as usize) % charset.len();
        password.push(charset.chars().nth(idx).unwrap());
    }
    
    Ok(password)
}

fn derive_key(password: &str) -> Vec<u8> {
    let mut result = vec![0u8; 32];
    for (i, byte) in password.as_bytes().iter().enumerate() {
        result[i % 32] ^= *byte;
    }
    result
}

fn current_time() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

struct ChaChaRng {
    state: [u32; 16],
}

impl ChaChaRng {
    fn new(seed: &[u8]) -> Self {
        let mut state = [0u32; 16];
        state[0] = 0x61707865;
        state[1] = 0x3320646e;
        state[2] = 0x79622d32;
        state[3] = 0x6b206574;
        
        for i in 0..8 {
            state[4 + i] = u32::from_le_bytes([
                seed.get(i * 4).copied().unwrap_or(0),
                seed.get(i * 4 + 1).copied().unwrap_or(0),
                seed.get(i * 4 + 2).copied().unwrap_or(0),
                seed.get(i * 4 + 3).copied().unwrap_or(0),
            ]);
        }
        
        Self { state }
    }
    
    fn next_u32(&mut self) -> u32 {
        self.state[12] = self.state[12].wrapping_add(1);
        
        for _ in 0..20 {
            quarter_round(&mut self.state, 0, 4, 8, 12);
            quarter_round(&mut self.state, 1, 5, 9, 13);
            quarter_round(&mut self.state, 2, 6, 10, 14);
            quarter_round(&mut self.state, 3, 7, 11, 15);
            quarter_round(&mut self.state, 0, 5, 10, 15);
            quarter_round(&mut self.state, 1, 6, 11, 12);
            quarter_round(&mut self.state, 2, 7, 8, 13);
            quarter_round(&mut self.state, 3, 4, 9, 14);
        }
        
        let mut output = [0u32; 16];
        for i in 0..16 {
            output[i] = self.state[i].wrapping_add(output[i]);
        }
        
        output[0]
    }
}

fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
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