package com.securevault.ui.screens

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Sync
import androidx.compose.material.icons.filled.SyncProblem
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(
    onBack: () -> Unit,
    onBiometricToggle: (Boolean) -> Unit,
    onAutoLockChange: (Int) -> Unit,
    onPasskeySetup: () -> Unit,
    onManualSync: () -> Unit = {}
) {
    var biometricEnabled by remember { mutableStateOf(true) }
    var autoLockMinutes by remember { mutableIntStateOf(5) }
    var syncStatus by remember { mutableStateOf(SyncUiStatus.Synced) } // Synced, Pending, Syncing
    
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Settings") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            androidx.compose.material.icons.Icons.Default.ArrowBack,
                            contentDescription = "Back"
                        )
                    }
                }
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
        ) {
            ListItem(
                headlineContent = { Text("Security") },
                supportingContent = { Text("Configure security settings") },
                modifier = Modifier.clickable {  }
            )
            
            HorizontalDivider()
            
            ListItem(
                headlineContent = { Text("Biometric Unlock") },
                trailingContent = {
                    Switch(
                        checked = biometricEnabled,
                        onCheckedChange = {
                            biometricEnabled = it
                            onBiometricToggle(it)
                        }
                    )
                }
            )
            
            ListItem(
                headlineContent = { Text("Auto-lock timeout") },
                trailingContent = {
                    Text("$autoLockMinutes min")
                }
            )
            
            Slider(
                value = autoLockMinutes.toFloat(),
                onValueChange = {
                    autoLockMinutes = it.toInt()
                    onAutoLockChange(it.toInt())
                },
                valueRange = 1f..30f,
                modifier = Modifier.padding(horizontal = 16.dp)
            )
            
            HorizontalDivider()
            
            // Sync Section
            ListItem(
                headlineContent = { Text("Sync") },
                supportingContent = { Text("Password sync across devices") }
            )
            
            // Sync Status Indicator
            ListItem(
                headlineContent = { Text("Sync Status") },
                leadingContent = {
                    when (syncStatus) {
                        SyncUiStatus.Synced -> Icon(
                            Icons.Default.CheckCircle,
                            contentDescription = "Synced",
                            tint = MaterialTheme.colorScheme.primary
                        )
                        SyncUiStatus.Pending -> Icon(
                            Icons.Default.SyncProblem,
                            contentDescription = "Pending",
                            tint = MaterialTheme.colorScheme.error
                        )
                        SyncUiStatus.Syncing -> CircularProgressIndicator(
                            modifier = Modifier.size(24.dp),
                            strokeWidth = 2.dp
                        )
                    }
                },
                supportingContent = {
                    Text(
                        when (syncStatus) {
                            SyncUiStatus.Synced -> "All devices synced"
                            SyncUiStatus.Pending -> "Waiting for sync"
                            SyncUiStatus.Syncing -> "Syncing..."
                        }
                    )
                }
            )
            
            // Manual Sync Button
            ListItem(
                headlineContent = { Text("Sync Now") },
                supportingContent = { Text("Force sync all pending passwords") },
                leadingContent = {
                    Icon(
                        Icons.Default.Sync,
                        contentDescription = "Sync"
                    )
                },
                modifier = Modifier.clickable {
                    syncStatus = SyncUiStatus.Syncing
                    onManualSync()
                }
            )
            
            HorizontalDivider()
            
            ListItem(
                headlineContent = { Text("Manage Passkeys") },
                supportingContent = { Text("View and manage passkey credentials") },
                modifier = Modifier.clickable { onPasskeySetup() }
            )
            
            HorizontalDivider()
            
            ListItem(
                headlineContent = { Text("About SecureVault") },
                supportingContent = { 
                    Column {
                        Text("Version 1.0")
                        Text("Post-quantum secure password manager")
                        Text("ML-KEM / ML-DSA / SPHINCS+")
                    }
                }
            )
        }
    }
}

enum class SyncUiStatus {
    Synced,
    Pending,
    Syncing
}