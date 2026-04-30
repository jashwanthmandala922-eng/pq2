package com.securevault.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.securevault.ui.components.GlassCard
import com.securevault.ui.theme.GlassColors

data class VaultEntry(
    val id: String,
    val title: String,
    val username: String?,
    val url: String?,
    val hasPassword: Boolean = true
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun VaultScreen(
    onEntryClick: (String) -> Unit,
    onAddEntry: () -> Unit,
    onSync: () -> Unit,
    onSettings: () -> Unit,
    onLock: () -> Unit
) {
    var searchQuery by remember { mutableStateOf("") }
    var showSearch by remember { mutableStateOf(false) }
    
    val entries = remember {
        listOf(
            VaultEntry("1", "Google", "user@gmail.com", "google.com"),
            VaultEntry("2", "GitHub", "dev@github.com", "github.com"),
            VaultEntry("3", "Twitter", "@username", "twitter.com"),
            VaultEntry("4", "Netflix", "user@email.com", "netflix.com"),
            VaultEntry("5", "Amazon", "user@amazon.com", "amazon.com")
        )
    }
    
    val filteredEntries = remember(searchQuery, entries) {
        if (searchQuery.isBlank()) entries
        else entries.filter {
            it.title.contains(searchQuery, ignoreCase = true) ||
            it.username?.contains(searchQuery, ignoreCase = true) == true
        }
    }
    
    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    if (showSearch) {
                        OutlinedTextField(
                            value = searchQuery,
                            onValueChange = { searchQuery = it },
                            modifier = Modifier.fillMaxWidth(),
                            placeholder = { Text("Search passwords...") },
                            singleLine = true,
                            colors = OutlinedTextFieldDefaults.colors(
                                focusedBorderColor = Color.Transparent,
                                unfocusedBorderColor = Color.Transparent
                            )
                        )
                    } else {
                        Text(
                            "SecureVault",
                            style = MaterialTheme.typography.headlineSmall
                        )
                    }
                },
                actions = {
                    if (showSearch) {
                        IconButton(onClick = { 
                            showSearch = false
                            searchQuery = ""
                        }) {
                            Icon(Icons.Default.Close, "Close")
                        }
                    } else {
                        IconButton(onClick = { showSearch = true }) {
                            Icon(Icons.Default.Search, "Search")
                        }
                    }
                    IconButton(onClick = onLock) {
                        Icon(Icons.Default.Lock, "Lock")
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = Color.Transparent
                )
            )
        },
        floatingActionButton = {
            FloatingActionButton(
                onClick = onAddEntry,
                containerColor = GlassColors.Primary
            ) {
                Icon(
                    Icons.Default.Add,
                    contentDescription = "Add",
                    tint = Color.White
                )
            }
        },
        containerColor = GlassColors.GlassBackground
    ) { padding ->
        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .background(
                    brush = Brush.verticalGradient(
                        colors = listOf(
                            GlassColors.GlassBackground,
                            GlassColors.Primary.copy(alpha = 0.03f)
                        )
                    )
                )
        ) {
            if (filteredEntries.isEmpty()) {
                EmptyVault(
                    hasSearch = searchQuery.isNotEmpty(),
                    onAddEntry = onAddEntry
                )
            } else {
                LazyColumn(
                    modifier = Modifier.fillMaxSize(),
                    contentPadding = PaddingValues(16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    items(filteredEntries) { entry ->
                        EntryCard(
                            entry = entry,
                            onClick = { onEntryClick(entry.id) }
                        )
                    }
                    
                    item {
                        Spacer(modifier = Modifier.height(72.dp))
                    }
                }
            }
        }
        
        // Bottom navigation
        BottomNavigation(
            modifier = Modifier
                .align(Alignment.BottomCenter)
                .background(
                    brush = Brush.verticalGradient(
                        colors = listOf(
                            Color.White.copy(alpha = 0.95f),
                            Color.White.copy(alpha = 0.9f)
                        )
                    )
                ),
            containerColor = Color.Transparent,
            elevation = 0.dp
        ) {
            BottomNavigationItem(
                selected = true,
                onClick = { },
                icon = { Icon(Icons.Default.Lock, null) },
                label = { Text("Vault") }
            )
            BottomNavigationItem(
                selected = false,
                onClick = onSync,
                icon = { Icon(Icons.Default.Sync, null) },
                label = { Text("Sync") }
            )
            BottomNavigationItem(
                selected = false,
                onClick = onSettings,
                icon = { Icon(Icons.Default.Settings, null) },
                label = { Text("Settings") }
            )
        }
    }
}

@Composable
fun EntryCard(
    entry: VaultEntry,
    onClick: () -> Unit
) {
    var showPassword by remember { mutableStateOf(false) }
    
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(
            containerColor = Color.White.copy(alpha = 0.7f)
        ),
        elevation = CardDefaults.cardElevation(defaultElevation = 2.dp)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            // Icon
            Box(
                modifier = Modifier
                    .size(48.dp)
                    .clip(CircleShape)
                    .background(
                        brush = Brush.linearGradient(
                            colors = listOf(
                                GlassColors.Primary.copy(alpha = 0.2f),
                                GlassColors.Accent.copy(alpha = 0.2f)
                            )
                        )
                    ),
                contentAlignment = Alignment.Center
            ) {
                Text(
                    entry.title.first().toString(),
                    style = MaterialTheme.typography.titleMedium,
                    color = GlassColors.Primary
                )
            }
            
            Spacer(modifier = Modifier.width(16.dp))
            
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    entry.title,
                    style = MaterialTheme.typography.titleMedium,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                entry.username?.let {
                    Text(
                        it,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }
            }
            
            IconButton(onClick = { /* Copy */ }) {
                Icon(
                    Icons.Default.ContentCopy,
                    contentDescription = "Copy",
                    tint = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}

@Composable
fun EmptyVault(
    hasSearch: Boolean,
    onAddEntry: () -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Icon(
            if (hasSearch) Icons.Default.SearchOff else Icons.Default.Lock,
            contentDescription = null,
            modifier = Modifier.size(80.dp),
            tint = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.5f)
        )
        
        Spacer(modifier = Modifier.height(16.dp))
        
        Text(
            if (hasSearch) "No results found" else "No passwords yet",
            style = MaterialTheme.typography.titleLarge,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        
        Text(
            if (hasSearch) "Try a different search" else "Add your first password",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.7f)
        )
        
        if (!hasSearch) {
            Spacer(modifier = Modifier.height(24.dp))
            
            Button(
                onClick = onAddEntry,
                shape = RoundedCornerShape(12.dp),
                colors = ButtonDefaults.buttonColors(
                    containerColor = GlassColors.Primary
                )
            ) {
                Icon(Icons.Default.Add, null)
                Spacer(modifier = Modifier.width(8.dp))
                Text("Add Password")
            }
        }
    }
}