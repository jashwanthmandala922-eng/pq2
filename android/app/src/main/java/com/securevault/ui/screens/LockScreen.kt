package com.securevault.ui.screens

import androidx.compose.animation.*
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.blur
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.securevault.ui.components.GlassCard
import com.securevault.ui.components.GlassButton
import com.securevault.ui.components.GlassOutlinedButton
import com.securevault.ui.components.PasswordStrengthIndicator
import com.securevault.ui.theme.GlassColors

enum class LoginStep {
    MASTER_PASSWORD,
    TOTP_CODE,
    AUTHENTICATED
}

@Composable
fun LockScreen(
    onUnlocked: (String) -> Unit,
    onPasskeyAuth: () -> Unit,
    onBiometricAuth: () -> Unit,
    onCreateVault: (String) -> Unit,
    totpEnabled: Boolean = false,
    passkeyAvailable: Boolean = false,
    biometricAvailable: Boolean = false
) {
    var currentStep by remember { mutableStateOf(LoginStep.MASTER_PASSWORD) }
    var password by remember { mutableStateOf("") }
    var confirmPassword by remember { mutableStateOf("") }
    var totpCode by remember { mutableStateOf("") }
    var showPassword by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    var loading by remember { mutableStateOf(false) }
    var isNewVault by remember { mutableStateOf(false) }
    
    val passwordStrength = remember(password) {
        when {
            password.length < 8 -> 20
            password.length < 12 -> 50
            password.length < 16 -> 70
            else -> 90
        } + if (password.any { it.isUpperCase() }) 5 else 0 +
           if (password.any { it.isLowerCase() }) 5 else 0 +
           if (password.any { it.isDigit() }) 5 else 0 +
           if (password.any { !it.isLetterOrDigit() }) 5 else 0
    }
    
    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(
                brush = Brush.verticalGradient(
                    colors = listOf(
                        GlassColors.GlassBackground,
                        GlassColors.Primary.copy(alpha = 0.05f),
                        GlassColors.Accent.copy(alpha = 0.05f)
                    )
                )
            )
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(24.dp)
                .blur(if (loading) 4.dp else 0.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            // Logo
            Box(
                modifier = Modifier
                    .size(100.dp)
                    .background(
                        brush = Brush.linearGradient(
                            colors = listOf(GlassColors.Primary, GlassColors.Accent)
                        ),
                        shape = RoundedCornerShape(24.dp)
                    ),
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    Icons.Default.Lock,
                    contentDescription = null,
                    tint = Color.White,
                    modifier = Modifier.size(48.dp)
                )
            }
            
            Spacer(modifier = Modifier.height(24.dp))
            
            Text("SecureVault", style = MaterialTheme.typography.headlineLarge, color = GlassColors.Primary)
            Text(
                if (currentStep == LoginStep.TOTP_CODE) "Enter TOTP Code" else "Post-quantum password manager",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            
            Spacer(modifier = Modifier.height(48.dp))
            
            GlassCard(modifier = Modifier.fillMaxWidth()) {
                AnimatedContent(
                    targetState = currentStep,
                    transitionSpec = {
                        slideInHorizontally { width -> width } + fadeIn() togetherWith
                                slideOutHorizontally { width -> -width } + fadeOut()
                    },
                    label = "login_step"
                ) { step ->
                    when (step) {
                        LoginStep.MASTER_PASSWORD -> {
                            Column {
                                Text(
                                    if (isNewVault) "Create Master Password" else "Master Password",
                                    style = MaterialTheme.typography.titleMedium,
                                    color = MaterialTheme.colorScheme.onSurface
                                )
                                
                                Spacer(modifier = Modifier.height(16.dp))
                                
                                OutlinedTextField(
                                    value = password,
                                    onValueChange = { password = it; error = null },
                                    modifier = Modifier.fillMaxWidth(),
                                    placeholder = { Text("Master Password") },
                                    singleLine = true,
                                    visualTransformation = if (showPassword) VisualTransformation.None else PasswordVisualTransformation(),
                                    trailingIcon = {
                                        IconButton(onClick = { showPassword = !showPassword }) {
                                            Icon(
                                                if (showPassword) Icons.Default.VisibilityOff else Icons.Default.Visibility,
                                                contentDescription = null
                                            )
                                        }
                                    },
                                    shape = RoundedCornerShape(12.dp),
                                    colors = OutlinedTextFieldDefaults.colors(
                                        focusedBorderColor = GlassColors.Primary,
                                        unfocusedBorderColor = Color.Gray.copy(alpha = 0.3f),
                                        focusedContainerColor = Color.White.copy(alpha = 0.5f),
                                        unfocusedContainerColor = Color.White.copy(alpha = 0.3f)
                                    )
                                )
                                
                                if (isNewVault) {
                                    Spacer(modifier = Modifier.height(8.dp))
                                    PasswordStrengthIndicator(strength = passwordStrength, modifier = Modifier.fillMaxWidth())
                                    
                                    Spacer(modifier = Modifier.height(12.dp))
                                    
                                    OutlinedTextField(
                                        value = confirmPassword,
                                        onValueChange = { confirmPassword = it },
                                        modifier = Modifier.fillMaxWidth(),
                                        placeholder = { Text("Confirm Password") },
                                        singleLine = true,
                                        visualTransformation = if (showPassword) VisualTransformation.None else PasswordVisualTransformation(),
                                        shape = RoundedCornerShape(12.dp),
                                        colors = OutlinedTextFieldDefaults.colors(
                                            focusedBorderColor = GlassColors.Primary,
                                            unfocusedBorderColor = Color.Gray.copy(alpha = 0.3f)
                                        )
                                    )
                                }
                                
                                if (error != null) {
                                    Spacer(modifier = Modifier.height(8.dp))
                                    Text(error!!, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                                }
                                
                                Spacer(modifier = Modifier.height(24.dp))
                                
                                Button(
                                    onClick = {
                                        if (isNewVault) {
                                            if (password.length < 8) {
                                                error = "Password must be at least 8 characters"
                                            } else if (password != confirmPassword) {
                                                error = "Passwords don't match"
                                            } else {
                                                onCreateVault(password)
                                            }
                                        } else if (totpEnabled) {
                                            currentStep = LoginStep.TOTP_CODE
                                        } else {
                                            onUnlocked(password)
                                        }
                                    },
                                    modifier = Modifier.fillMaxWidth().height(50.dp),
                                    shape = RoundedCornerShape(12.dp),
                                    colors = ButtonDefaults.buttonColors(containerColor = GlassColors.Primary)
                                ) {
                                    Text(if (isNewVault) "Create Vault" else if (totpEnabled) "Next" else "Unlock")
                                }
                                
                                if (!isNewVault) {
                                    Spacer(modifier = Modifier.height(12.dp))
                                    
                                    Row(
                                        modifier = Modifier.fillMaxWidth(),
                                        horizontalArrangement = Arrangement.Center
                                    ) {
                                        TextButton(onClick = { isNewVault = true }) {
                                            Text("Create New Vault")
                                        }
                                    }
                                }
                            }
                        }
                        
                        LoginStep.TOTP_CODE -> {
                            Column {
                                Row(
                                    verticalAlignment = Alignment.CenterVertically,
                                    modifier = Modifier.fillMaxWidth()
                                ) {
                                    IconButton(onClick = { currentStep = LoginStep.MASTER_PASSWORD }) {
                                        Icon(Icons.Default.ArrowBack, "Back")
                                    }
                                    Text("Two-Factor Authentication", style = MaterialTheme.typography.titleMedium)
                                }
                                
                                Spacer(modifier = Modifier.height(16.dp))
                                
                                Text(
                                    "Enter the 6-digit code from your authenticator app",
                                    style = MaterialTheme.typography.bodyMedium,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                                
                                Spacer(modifier = Modifier.height(24.dp))
                                
                                OutlinedTextField(
                                    value = totpCode,
                                    onValueChange = { if (it.length <= 6 && it.all { c -> c.isDigit() }) totpCode = it },
                                    modifier = Modifier.fillMaxWidth(),
                                    placeholder = { Text("000000") },
                                    singleLine = true,
                                    textStyle = MaterialTheme.typography.headlineMedium.copy(textAlign = TextAlign.Center),
                                    shape = RoundedCornerShape(12.dp),
                                    colors = OutlinedTextFieldDefaults.colors(
                                        focusedBorderColor = GlassColors.Accent,
                                        unfocusedBorderColor = Color.Gray.copy(alpha = 0.3f)
                                    )
                                )
                                
                                if (error != null) {
                                    Spacer(modifier = Modifier.height(8.dp))
                                    Text(error!!, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                                }
                                
                                Spacer(modifier = Modifier.height(24.dp))
                                
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.spacedBy(12.dp)
                                ) {
                                    OutlinedButton(
                                        onClick = { currentStep = LoginStep.MASTER_PASSWORD },
                                        modifier = Modifier.weight(1f),
                                        shape = RoundedCornerShape(12.dp)
                                    ) {
                                        Text("Back")
                                    }
                                    
                                    Button(
                                        onClick = { onUnlocked(password) },
                                        modifier = Modifier.weight(1f),
                                        enabled = totpCode.length == 6,
                                        shape = RoundedCornerShape(12.dp),
                                        colors = ButtonDefaults.buttonColors(containerColor = GlassColors.Accent)
                                    ) {
                                        Text("Verify")
                                    }
                                }
                            }
                        }
                        
                        LoginStep.AUTHENTICATED -> {
                            Column(
                                horizontalAlignment = Alignment.CenterHorizontally,
                                modifier = Modifier.padding(32.dp)
                            ) {
                                Icon(
                                    Icons.Default.CheckCircle,
                                    contentDescription = null,
                                    tint = GlassColors.Accent,
                                    modifier = Modifier.size(64.dp)
                                )
                                Spacer(modifier = Modifier.height(16.dp))
                                Text("Authenticated!", style = MaterialTheme.typography.titleLarge)
                            }
                        }
                    }
                }
            }
            
            Spacer(modifier = Modifier.height(24.dp))
            
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                if (passkeyAvailable) {
                    GlassOutlinedButton(
                        onClick = onPasskeyAuth,
                        modifier = Modifier.weight(1f)
                    ) {
                        Icon(Icons.Default.Key, contentDescription = null, modifier = Modifier.size(20.dp))
                        Spacer(modifier = Modifier.width(8.dp))
                        Text("Passkey", maxLines = 1)
                    }
                }
                
                if (biometricAvailable) {
                    GlassOutlinedButton(
                        onClick = onBiometricAuth,
                        modifier = Modifier.weight(1f)
                    ) {
                        Icon(Icons.Default.Fingerprint, contentDescription = null, modifier = Modifier.size(20.dp))
                        Spacer(modifier = Modifier.width(8.dp))
                        Text("Biometric", maxLines = 1)
                    }
                }
            }
            
            Spacer(modifier = Modifier.height(48.dp))
            
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Text(
                    if (totpEnabled) "ML-KEM • Argon2id • TOTP" else "ML-KEM • Argon2id",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Text(
                    "Post-quantum secure",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}