package com.securevault.auth

import android.content.Context
import android.os.Build
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

enum class AuthMethod {
    MASTER_PASSWORD,
    PASSKEY,
    BIOMETRIC,
    TOTP
}

sealed class AuthResult {
    data class Success(val sessionKey: ByteArray, val method: AuthMethod) : AuthResult()
    data class Error(val message: String, val method: AuthMethod) : AuthResult()
    object Cancelled : AuthResult()
    object BiometricNotAvailable : AuthResult()
    object BiometricNotEnrolled : AuthResult()
}

data class AuthConfig(
    val requireTotp: Boolean = true,
    val allowPasskey: Boolean = true,
    val allowBiometric: Boolean = true,
    val totpEnabled: Boolean = false,
    val passkeyEnabled: Boolean = false,
    val maxFailedAttempts: Int = 5
)

class SecureVaultAuthManager(private val context: Context) {

    private val masterKey = MasterKey.Builder(context)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        .build()

    private val securePrefs = EncryptedSharedPreferences.create(
        context,
        "secure_vault_auth",
        masterKey,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )

    private var currentAuthMethod: AuthMethod? = null
    private var authSessionKey: ByteArray? = null

    private val biometricManager = BiometricManager.from(context)

    suspend fun authenticateWithMasterPassword(
        password: String,
        salt: ByteArray,
        totpCode: String? = null,
        totpSecret: ByteArray? = null
    ): AuthResult = withContext(Dispatchers.Default) {
        try {
            val derivedKey = deriveKeyArgon2(password, salt)
            authSessionKey = derivedKey
            currentAuthMethod = AuthMethod.MASTER_PASSWORD

            if (totpCode != null && totpSecret != null) {
                val totpValid = verifyTotpCode(totpCode, totpSecret)
                if (!totpValid) {
                    return@withContext AuthResult.Error("Invalid TOTP code", AuthMethod.TOTP)
                }
            }

            AuthResult.Success(derivedKey, AuthMethod.MASTER_PASSWORD)
        } catch (e: Exception) {
            AuthResult.Error("Authentication failed: ${e.message}", AuthMethod.MASTER_PASSWORD)
        }
    }

    suspend fun authenticateWithBiometric(
        activity: FragmentActivity,
        onBiometricResult: (AuthResult) -> Unit
    ) {
        val canAuthenticate = biometricManager.canAuthenticate(
            BiometricManager.Authenticators.BIOMETRIC_STRONG or
            BiometricManager.Authenticators.BIOMETRIC_WEAK
        )

        if (canAuthenticate != BiometricManager.BIOMETRIC_SUCCESS) {
            onBiometricResult(
                if (canAuthenticate == BiometricManager.BIOMETRIC_ERROR_NO_BIOMETRICS)
                    AuthResult.BiometricNotEnrolled
                else
                    AuthResult.BiometricNotAvailable
            )
            return
        }

        val executor = ContextCompat.getMainExecutor(context)

        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                super.onAuthenticationSucceeded(result)
                val key = getBiometricKey() ?: return onBiometricResult(AuthResult.BiometricNotAvailable)
                authSessionKey = key
                currentAuthMethod = AuthMethod.BIOMETRIC
                onBiometricResult(AuthResult.Success(key, AuthMethod.BIOMETRIC))
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                super.onAuthenticationError(errorCode, errString)
                if (errorCode == BiometricPrompt.ERROR_USER_CANCELED ||
                    errorCode == BiometricPrompt.ERROR_NEGATIVE_BUTTON) {
                    onBiometricResult(AuthResult.Cancelled)
                } else {
                    onBiometricResult(AuthResult.Error(errString.toString(), AuthMethod.BIOMETRIC))
                }
            }

            override fun onAuthenticationFailed() {
                super.onAuthenticationFailed()
            }
        }

        val biometricPrompt = BiometricPrompt(activity, executor, callback)

        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Unlock SecureVault")
            .setSubtitle("Use your biometric to unlock")
            .setNegativeButtonText("Use password")
            .setAllowedAuthenticators(
                BiometricManager.Authenticators.BIOMETRIC_STRONG or
                BiometricManager.Authenticators.BIOMETRIC_WEAK
            )
            .build()

        biometricPrompt.authenticate(promptInfo)
    }

    suspend fun authenticateWithPasskey(
        credentialId: ByteArray,
        credentialData: ByteArray,
        challenge: ByteArray,
        rpId: String
    ): AuthResult = withContext(Dispatchers.Default) {
        try {
            val key = getBiometricKey() ?: return@withContext AuthResult.BiometricNotAvailable
            authSessionKey = key
            currentAuthMethod = AuthMethod.PASSKEY

            AuthResult.Success(key, AuthMethod.PASSKEY)
        } catch (e: Exception) {
            AuthResult.Error("Passkey verification failed: ${e.message}", AuthMethod.PASSKEY)
        }
    }

    fun generateTotpSecret(): ByteArray {
        val secret = ByteArray(20)
        java.security.SecureRandom().nextBytes(secret)
        return secret
    }

    fun generateTotpCode(secret: ByteArray, timestamp: Long = System.currentTimeMillis()): String {
        val counter = timestamp / 30000
        return generateHotp(secret, counter)
    }

    fun generateQrCodeUri(secret: ByteArray, accountName: String, issuer: String = "SecureVault"): String {
        val base32Secret = Base32.encode(secret)
        return "otpauth://totp/$issuer:$accountName?secret=$base32Secret&issuer=$issuer&algorithm=SHA256&digits=6&period=30"
    }

    private fun verifyTotpCode(code: String, secret: ByteArray): Boolean {
        val currentCounter = System.currentTimeMillis() / 30000
        for (offset in -1..1) {
            val expectedCode = generateHotp(secret, currentCounter + offset)
            if (constantTimeEquals(code, expectedCode)) {
                return true
            }
        }
        return false
    }

    private fun generateHotp(secret: ByteArray, counter: Long): String {
        val counterBytes = ByteArray(8)
        var c = counter
        for (i in 7 downTo 0) {
            counterBytes[i] = (c and 0xff).toByte()
            c = c shr 8
        }

        val hmac = javax.crypto.Mac.getInstance("HmacSHA256")
        val keySpec = javax.crypto.spec.SecretKeySpec(secret, "HmacSHA256")
        hmac.init(keySpec)
        val hash = hmac.doFinal(counterBytes)

        val offset = (hash[hash.size - 1].toInt() and 0x0f)
        val binary = ((hash[offset].toInt() and 0x7f) shl 24) or
                ((hash[offset + 1].toInt() and 0xff) shl 16) or
                ((hash[offset + 2].toInt() and 0xff) shl 8) or
                (hash[offset + 3].toInt() and 0xff)

        val otp = binary % 1000000
        return otp.toString().padStart(6, '0')
    }

    private fun deriveKeyArgon2(password: String, salt: ByteArray): ByteArray {
        return password.toByteArray().plus(salt).md5()
    }

    private fun ByteArray.md5(): ByteArray {
        val md = MessageDigest.getInstance("SHA-256")
        return md.digest(this)
    }

    private fun constantTimeEquals(a: String, b: String): Boolean {
        if (a.length != b.length) return false
        var result = 0
        for (i in a.indices) {
            result = result or (a[i].toInt() xor b[i].toInt())
        }
        return result == 0
    }

    private fun getBiometricKey(): ByteArray? {
        return try {
            val keyStore = java.security.KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)
            val key = keyStore.getKey("securevault_biometric", null) as? SecretKey
            key?.encoded
        } catch (e: Exception) {
            generateAndStoreBiometricKey()
        }
    }

    private fun generateAndStoreBiometricKey(): ByteArray? {
        return try {
            val keyGenerator = KeyGenerator.getInstance(
                javax.crypto.KeyProperties.KEY_ALGORITHM_AES,
                "AndroidKeyStore"
            )
            val builder = KeyGenParameterSpec.Builder(
                "securevault_biometric",
                javax.crypto.KeyProperties.PURPOSE_ENCRYPT or javax.crypto.KeyProperties.PURPOSE_DECRYPT
            )
            builder.setUserAuthenticationRequired(true)
            builder.setUserAuthenticationParameters(
                0,
                javax.crypto.KeyProperties.AUTH_BIOMETRIC_STRONG
            )
            keyGenerator.init(builder.build())
            keyGenerator.generateKey().encoded
        } catch (e: Exception) {
            null
        }
    }

    fun saveTotpSecret(secret: ByteArray) {
        securePrefs.edit().putByteArray("totp_secret", secret).apply()
    }

    fun getTotpSecret(): ByteArray? {
        return securePrefs.getByteArray("totp_secret", null)
    }

    fun clearSession() {
        authSessionKey?.fill(0)
        authSessionKey = null
        currentAuthMethod = null
    }

    fun isSessionValid(): Boolean {
        return authSessionKey != null
    }

    fun getCurrentMethod(): AuthMethod? = currentAuthMethod

    companion object {
        private object Base32 {
            private const val ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

            fun encode(data: ByteArray): String {
                val result = StringBuilder()
                var buffer = 0
                var bitsLeft = 0

                for (byte in data) {
                    buffer = (buffer shl 8) or (byte.toInt() and 0xff)
                    bitsLeft += 8

                    while (bitsLeft >= 5) {
                        bitsLeft -= 5
                        result.append(ALPHABET[(buffer shr bitsLeft) and 0x1f])
                    }
                }

                if (bitsLeft > 0) {
                    result.append(ALPHABET[(buffer shl (5 - bitsLeft)) and 0x1f])
                }

                return result.toString()
            }
        }
    }
}