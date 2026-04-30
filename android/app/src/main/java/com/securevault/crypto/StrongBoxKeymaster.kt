package com.securevault.crypto

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.util.Log
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.Certificate
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec

class StrongBoxKeymaster(context: Context) {
    
    private val keyStore: KeyStore = KeyStore.getInstance("AndroidKeyStore").apply {
        load(null)
    }
    
    private val keymasterProvider = "AndroidKeyStore"
    private val keyAlias = "SecureVault-StrongBox-Master"
    private val keyTag = "SecureVault-Stored-Key"
    
    sealed class KeymasterResult {
        data class Success(val data: ByteArray) : KeymasterResult()
        data class Error(val message: String) : KeymasterResult()
        object NotAvailable : KeymasterResult()
        object HardwareNotPresent : KeymasterResult()
    }
    
    fun isStrongBoxAvailable(): Boolean {
        return try {
            val keyGenerator = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES,
                keymasterProvider
            )
            
            val specBuilder = KeyGenParameterSpec.Builder(
                keyAlias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setIsStrongBoxBacked(true)
            
            keyGenerator.init(specBuilder.build())
            keyGenerator.generateKey()
            
            true
        } catch (e: Exception) {
            Log.e("StrongBox", "StrongBox not available: ${e.message}")
            false
        }
    }
    
    fun generateStrongBoxKey(enableBiometric: Boolean = true): KeymasterResult {
        return try {
            val keyGenerator = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES,
                keymasterProvider
            )
            
            val specBuilder = KeyGenParameterSpec.Builder(
                keyAlias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setIsStrongBoxBacked(true)
                .setRandomizedEncryptionRequired(true)
            
            if (enableBiometric) {
                specBuilder.setUserAuthenticationRequired(true)
                specBuilder.setUserAuthenticationParameters(
                    0,
                    KeyProperties.AUTH_BIOMETRIC_STRONG
                )
                specBuilder.setInvalidatedByBiometricEnrollment(true)
            }
            
            keyGenerator.init(specBuilder.build())
            keyGenerator.generateKey()
            
            KeymasterResult.Success(ByteArray(0))
        } catch (e: Exception) {
            KeymasterResult.Error("Failed to generate key: ${e.message}")
        }
    }
    
    fun encryptWithStrongBox(data: ByteArray): KeymasterResult {
        return try {
            val key = getKey() ?: return generateStrongBoxKey().let {
                encryptWithStrongBox(data)
            }
            
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, key)
            
            val encrypted = cipher.doFinal(data)
            val iv = cipher.iv
            
            val result = ByteArray(iv.size + encrypted.size)
            result.copyOfRange(0, iv.size).let { result.also { r -> 
                System.arraycopy(iv, 0, r, 0, iv.size)
            }}
            System.arraycopy(encrypted, 0, result, iv.size, encrypted.size)
            
            KeymasterResult.Success(result)
        } catch (e: Exception) {
            KeymasterResult.Error("Encryption failed: ${e.message}")
        }
    }
    
    fun decryptWithStrongBox(encryptedData: ByteArray): KeymasterResult {
        return try {
            val key = getKey() ?: return KeymasterResult.Error("Key not found")
            
            val iv = encryptedData.copyOfRange(0, 12)
            val ciphertext = encryptedData.copyOfRange(12, encryptedData.size)
            
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val spec = GCMParameterSpec(128, iv)
            cipher.init(Cipher.DECRYPT_MODE, key, spec)
            
            val decrypted = cipher.doFinal(ciphertext)
            
            KeymasterResult.Success(decrypted)
        } catch (e: Exception) {
            KeymasterResult.Error("Decryption failed: ${e.message}")
        }
    }
    
    fun storeEncryptionKey(keyMaterial: ByteArray): KeymasterResult {
        return encryptWithStrongBox(keyMaterial)
    }
    
    fun retrieveEncryptionKey(): KeymasterResult {
        return try {
            val stored = getStoredKeyMaterial() ?: return KeymasterResult.Error("No stored key")
            decryptWithStrongBox(stored)
        } catch (e: Exception) {
            KeymasterResult.Error("Failed to retrieve key: ${e.message}")
        }
    }
    
    fun deleteStrongBoxKey(): KeymasterResult {
        return try {
            if (keyStore.containsAlias(keyAlias)) {
                keyStore.deleteEntry(keyAlias)
            }
            KeymasterResult.Success(ByteArray(0))
        } catch (e: Exception) {
            KeymasterResult.Error("Failed to delete key: ${e.message}")
        }
    }
    
    fun isHardwareBacked(): Boolean {
        return try {
            val key = getKey() ?: return false
            val factory = SecretKeyFactory.getInstance(key.algorithm, keymasterProvider)
            val keyInfo = factory.getKeySpec(key, KeyInfo::class.java) as KeyInfo
            keyInfo.isInsideSecureHardware
        } catch (e: Exception) {
            false
        }
    }
    
    private fun getKey(): SecretKey? {
        return try {
            keyStore.getKey(keyAlias, null) as? SecretKey
        } catch (e: Exception) {
            null
        }
    }
    
    private fun getStoredKeyMaterial(): ByteArray? {
        val prefs = context.getSharedPreferences("secure_vault_keys", Context.MODE_PRIVATE)
        val stored = prefs.getByteArray("encrypted_key_material", null)
        
        return stored
            ?.let {
                val iv = prefs.getByteArray("encrypted_key_iv", null)
                if (iv != null) {
                    val combined = ByteArray(iv.size + it.size)
                    System.arraycopy(iv, 0, combined, 0, iv.size)
                    System.arraycopy(it, 0, combined, iv.size, it.size)
                    combined
                } else null
            }
    }
    
    companion object {
        private const val GCM_TAG_LENGTH = 128
        private const val KEY_SIZE = 256
    }
}

class HardwareKeyManager(private val context: Context) {
    
    private val strongBox = StrongBoxKeymaster(context)
    
    fun initialize(masterPassword: String): Boolean {
        if (strongBox.isStrongBoxAvailable()) {
            val result = strongBox.generateStrongBoxKey(enableBiometric = true)
            return when (result) {
                is StrongBoxKeymaster.KeymasterResult.Success -> true
                is StrongBoxKeymaster.KeymasterResult.Error -> {
                    Log.e("HardwareKey", result.message)
                    false
                }
                else -> false
            }
        }
        
        return createFallbackKey(masterPassword)
    }
    
    private fun createFallbackKey(password: String): Boolean {
        return try {
            val keyGenerator = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES,
                "AndroidKeyStore"
            )
            
            val keySpec = KeyGenParameterSpec.Builder(
                "SecureVault-Fallback-Key",
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setUserAuthenticationRequired(true)
                .setUserAuthenticationParameters(
                    300,
                    KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL
                )
                .build()
            
            keyGenerator.init(keySpec)
            keyGenerator.generateKey()
            
            true
        } catch (e: Exception) {
            Log.e("HardwareKey", "Fallback key creation failed: ${e.message}")
            false
        }
    }
    
    fun encryptSeed(seed: ByteArray): ByteArray? {
        val result = strongBox.encryptWithStrongBox(seed)
        
        return when (result) {
            is StrongBoxKeymaster.KeymasterResult.Success -> result.data
            else -> null
        }
    }
    
    fun decryptSeed(encryptedSeed: ByteArray): ByteArray? {
        val result = strongBox.decryptWithStrongBox(encryptedSeed)
        
        return when (result) {
            is StrongBoxKeymaster.KeymasterResult.Success -> result.data
            else -> null
        }
    }
    
    fun isSecure(): Boolean {
        return strongBox.isStrongBoxAvailable() && strongBox.isHardwareBacked()
    }
}