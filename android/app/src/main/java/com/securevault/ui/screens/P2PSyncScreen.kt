package com.securevault.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.lifecycle.ViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun P2PSyncScreen(
    viewModel: SyncViewModel,
    onBack: () -> Unit,
    onStartSync: () -> Unit
) {
    val uiState by viewModel.uiState.collectAsState()
    
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("P2P Sync") },
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
                .padding(16.dp)
        ) {
            Card(
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(
                    modifier = Modifier.padding(16.dp)
                ) {
                    Text(
                        "Sync Status",
                        style = MaterialTheme.typography.titleMedium
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    Row {
                        Text(
                            if (uiState.isConnected) "Connected" else "Disconnected",
                            color = if (uiState.isConnected) {
                                MaterialTheme.colorScheme.primary
                            } else {
                                MaterialTheme.colorScheme.error
                            }
                        )
                    }
                }
            }
            
            Spacer(modifier = Modifier.height(16.dp))
            
            Card(
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(
                    modifier = Modifier.padding(16.dp)
                ) {
                    Text(
                        "Available Peers",
                        style = MaterialTheme.typography.titleMedium
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    
                    if (uiState.peers.isEmpty()) {
                        Text(
                            "No peers found",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    } else {
                        uiState.peers.forEach { peer ->
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(vertical = 4.dp)
                            ) {
                                Text(peer.name)
                                Spacer(modifier = Modifier.weight(1f))
                                Text(peer.status)
                            }
                        }
                    }
                }
            }
            
            Spacer(modifier = Modifier.height(16.dp))
            
            OutlinedButton(
                onClick = { viewModel.startDiscovery() },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Find Peers")
            }
            
            Spacer(modifier = Modifier.height(8.dp))
            
            Button(
                onClick = onStartSync,
                modifier = Modifier.fillMaxWidth(),
                enabled = uiState.peers.isNotEmpty()
            ) {
                Text("Sync Now")
            }
            
            Spacer(modifier = Modifier.height(16.dp))
            
            Card(
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(
                    modifier = Modifier.padding(16.dp)
                ) {
                    Text(
                        "Last Sync: ${uiState.lastSync ?: "Never"}",
                        style = MaterialTheme.typography.bodySmall
                    )
                    Text(
                        "Entries: ${uiState.entryCount}",
                        style = MaterialTheme.typography.bodySmall
                    )
                }
            }
        }
    }
}

class SyncViewModel : ViewModel() {
    private val _uiState = MutableStateFlow(SyncUiState())
    val uiState: StateFlow<SyncUiState> = _uiState
    
    fun startDiscovery() {
        // Start P2P discovery via native
    }
}

data class SyncUiState(
    val isConnected: Boolean = false,
    val peers: List<PeerStatus> = emptyList(),
    val lastSync: String? = null,
    val entryCount: Int = 0
)

data class PeerStatus(
    val name: String,
    val status: String
)