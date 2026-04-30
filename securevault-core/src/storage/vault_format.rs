use serde::{Deserialize, Serialize};
use std::io::{Read, Write, Seek, SeekFrom};

pub const VAULT_MAGIC: [u8; 4] = [0x53, 0x56, 0x4C, 0x54];  // "SVLT"
pub const VAULT_FORMAT_VERSION: u32 = 3;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VaultFileHeader {
    pub magic: [u8; 4],
    pub version: u32,
    pub header_length: u32,
    pub created_at: u64,
    pub modified_at: u64,
    pub total_entries: u32,
    pub kdf_params: KdfParameters,
    pub kem_params: KemParameters,
    pub cipher_params: CipherParameters,
    pub authentication: AuthParams,
    pub flags: VaultFlags,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KdfParameters {
    pub algorithm: KdfAlgorithm,
    pub salt: [u8; 32],
    pub memory_kb: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum KdfAlgorithm {
    Argon2id,
    Pbkdf2Sha256,
    Pbkdf2Sha512,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KemParameters {
    pub classical_algorithm: ClassicalKem,
    pub quantum_algorithm: QuantumKem,
    pub encapsulation_data: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum ClassicalKem {
    X25519,
    EcdhP256,
    EcdhP384,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum QuantumKem {
    MlKem768,
    MlKem1024,
    MlDilithium,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CipherParameters {
    pub algorithm: CipherAlgorithm,
    pub nonce: [u8; 12],
    pub tag_length: u8,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum CipherAlgorithm {
    Aes256Gcm,
    ChaCha20Poly1305,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthParams {
    pub scheme: AuthScheme,
    pub totp_enabled: bool,
    pub passkey_enabled: bool,
    pub biometric_enabled: bool,
    pub password_hash: Option<[u8; 32]>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum AuthScheme {
    PasswordOnly,
    PasswordTotp,
    PasskeyOnly,
    BiometricOnly,
    HybridAny,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VaultFlags {
    pub compressed: bool,
    pub encrypted: bool,
    pub indexed: bool,
}

impl Default for VaultFileHeader {
    fn default() -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let salt = {
            let mut s = [0u8; 32];
            let mut rng = crate::rng::ChaChaRng::new(b"SecureVault-salt!");
            rng.fill_bytes(&mut s);
            s
        };

        Self {
            magic: VAULT_MAGIC,
            version: VAULT_FORMAT_VERSION,
            header_length: 0,
            created_at: now,
            modified_at: now,
            total_entries: 0,
            kdf_params: KdfParameters {
                algorithm: KdfAlgorithm::Argon2id,
                salt,
                memory_kb: 65536,
                iterations: 3,
                parallelism: 4,
            },
            kem_params: KemParameters {
                classical_algorithm: ClassicalKem::X25519,
                quantum_algorithm: QuantumKem::MlKem768,
                encapsulation_data: Vec::new(),
            },
            cipher_params: CipherParameters {
                algorithm: CipherAlgorithm::Aes256Gcm,
                nonce: [0u8; 12],
                tag_length: 16,
            },
            authentication: AuthParams {
                scheme: AuthScheme::PasswordOnly,
                totp_enabled: false,
                passkey_enabled: false,
                biometric_enabled: true,
                password_hash: None,
            },
            flags: VaultFlags {
                compressed: false,
                encrypted: true,
                indexed: true,
            },
        }
    }
}

impl VaultFileHeader {
    pub fn serialize(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(data)
    }

    pub fn validate(&self) -> Result<(), VaultFormatError> {
        if &self.magic != &VAULT_MAGIC {
            return Err(VaultFormatError::InvalidMagic);
        }
        
        if self.version > VAULT_FORMAT_VERSION {
            return Err(VaultFormatError::UnsupportedVersion(self.version));
        }
        
        if self.header_length as usize > 65536 {
            return Err(VaultFormatError::HeaderTooLarge);
        }
        
        Ok(())
    }

    pub fn update_modified(&mut self) {
        self.modified_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }

    pub fn forward_compatible(&self) -> bool {
        match self.version {
            1 | 2 | 3 => true,
            _ => false,
        }
    }

    pub fn migration_path(&self) -> Vec<u32> {
        let mut migrations = Vec::new();
        
        if self.version < 2 {
            migrations.push(2);
        }
        if self.version < 3 {
            migrations.push(3);
        }
        
        migrations
    }
}

#[derive(Debug, thiserror::Error)]
pub enum VaultFormatError {
    #[error("Invalid vault file magic number")]
    InvalidMagic,
    
    #[error("Unsupported vault format version: {0}")]
    UnsupportedVersion(u32),
    
    #[error("Vault header too large")]
    HeaderTooLarge,
    
    #[error("Serialization error: {0}")]
    SerializationError(String),
    
    #[error("Invalid checksum")]
    ChecksumMismatch,
    
    #[error("IO error: {0}")]
    IoError(String),
}

pub struct VaultFileWriter<W: Write + Seek> {
    writer: W,
    header: VaultFileHeader,
}

impl<W: Write + Seek> VaultFileWriter<W> {
    pub fn new(writer: W) -> Self {
        Self {
            writer,
            header: VaultFileHeader::default(),
        }
    }

    pub fn with_header(writer: W, header: VaultFileHeader) -> Self {
        Self { writer, header }
    }

    pub fn write_header(&mut self) -> Result<(), VaultFormatError> {
        let header_data = self.header.serialize();
        self.header.header_length = header_data.len() as u32;
        
        let final_header_data = self.header.serialize();
        
        self.writer.write_all(&VAULT_MAGIC)?;
        self.writer.write_all(&self.header.version.to_le_bytes())?;
        
        let len = final_header_data.len() as u32;
        self.writer.write_all(&len.to_le_bytes())?;
        
        self.writer.write_all(&final_header_data)?;
        
        Ok(())
    }

    pub fn write_entry(&mut self, entry_data: &[u8]) -> Result<(), VaultFormatError> {
        let len = entry_data.len() as u32;
        self.writer.write_all(&len.to_le_bytes())?;
        self.writer.write_all(entry_data)?;
        
        Ok(())
    }

    pub fn finalize(mut self) -> Result<W, VaultFormatError> {
        self.header.total_entries += 1;
        self.writer.seek(SeekFrom::Start(0))?;
        self.write_header()?;
        
        Ok(self.writer)
    }
}

pub struct VaultFileReader<R: Read + Seek> {
    reader: R,
    pub header: VaultFileHeader,
}

impl<R: Read + Seek> VaultFileReader<R> {
    pub fn new(reader: R) -> Result<Self, VaultFormatError> {
        let mut reader = reader;
        
        let mut magic = [0u8; 4];
        reader.read_exact(&mut magic)?;
        
        if &magic != &VAULT_MAGIC {
            return Err(VaultFormatError::InvalidMagic);
        }
        
        let mut version_bytes = [0u8; 4];
        reader.read_exact(&mut version_bytes)?;
        let version = u32::from_le_bytes(version_bytes);
        
        let mut len_bytes = [0u8; 4];
        reader.read_exact(&mut len_bytes)?;
        let header_len = u32::from_le_bytes(len_bytes);
        
        let mut header_data = vec![0u8; header_len as usize];
        reader.read_exact(&mut header_data)?;
        
        let mut header = VaultFileHeader::deserialize(&header_data)
            .map_err(|e| VaultFormatError::SerializationError(e.to_string()))?;
        
        header.validate()?;
        
        Ok(Self { reader, header })
    }

    pub fn read_entry(&mut self) -> Result<Vec<u8>, VaultFormatError> {
        let mut len_bytes = [0u8; 4];
        self.reader.read_exact(&mut len_bytes)?;
        let len = u32::from_le_bytes(len_bytes);
        
        let mut data = vec![0u8; len as usize];
        self.reader.read_exact(&mut data)?;
        
        Ok(data)
    }

    pub fn read_all_entries(&mut self) -> Result<Vec<Vec<u8>>, VaultFormatError> {
        let mut entries = Vec::new();
        
        loop {
            match self.read_entry() {
                Ok(entry) => entries.push(entry),
                Err(VaultFormatError::IoError(_)) => break,
                Err(e) => return Err(e),
            }
        }
        
        Ok(entries)
    }
}

pub fn detect_format_version(data: &[u8]) -> Option<u32> {
    if data.len() < 8 {
        return None;
    }
    
    if &data[0..4] == &VAULT_MAGIC {
        let version = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        return Some(version);
    }
    
    None
}

pub fn migrate_vault(data: &[u8], from_version: u32, to_version: u32) -> Result<Vec<u8>, VaultFormatError> {
    if from_version >= to_version {
        return Ok(data.to_vec());
    }
    
    match (from_version, to_version) {
        (1, 2) => migrate_v1_to_v2(data),
        (2, 3) => migrate_v2_to_v3(data),
        _ => Err(VaultFormatError::UnsupportedVersion(from_version)),
    }
}

fn migrate_v1_to_v2(data: &[u8]) -> Result<Vec<u8>, VaultFormatError> {
    Ok(data.to_vec())
}

fn migrate_v2_to_v3(data: &[u8]) -> Result<Vec<u8>, VaultFormatError> {
    Ok(data.to_vec())
}