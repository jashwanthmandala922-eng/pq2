package com.securevault

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import com.securevault.ui.screens.*
import com.securevault.ui.theme.SecureVaultTheme

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        
        setContent {
            SecureVaultTheme {
                MainApp()
            }
        }
    }
}

sealed class Screen(val route: String) {
    object Lock : Screen("lock")
    object Vault : Screen("vault")
    object Entry : Screen("entry/{entryId}") {
        fun createRoute(entryId: String) = "entry/$entryId"
    }
    object AddEntry : Screen("add")
    object Settings : Screen("settings")
    object Sync : Screen("sync")
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MainApp() {
    val navController = rememberNavController()
    var isUnlocked by remember { mutableStateOf(false) }
    
    Scaffold(
        modifier = Modifier.fillMaxSize(),
        containerColor = MaterialTheme.colorScheme.background
    ) { padding ->
        NavHost(
            navController = navController,
            startDestination = if (isUnlocked) Screen.Vault.route else Screen.Lock.route,
            modifier = Modifier.padding(padding)
        ) {
            composable(Screen.Lock.route) {
                LockScreen(
                    onUnlocked = {
                        isUnlocked = true
                        navController.navigate(Screen.Vault.route) {
                            popUpTo(Screen.Lock.route) { inclusive = true }
                        }
                    },
                    onPasskeyAuth = {
                        isUnlocked = true
                        navController.navigate(Screen.Vault.route)
                    },
                    onCreateVault = { password ->
                        isUnlocked = true
                        navController.navigate(Screen.Vault.route)
                    }
                )
            }
            
            composable(Screen.Vault.route) {
                VaultScreen(
                    onEntryClick = { entryId ->
                        navController.navigate(Screen.Entry.createRoute(entryId))
                    },
                    onAddEntry = {
                        navController.navigate(Screen.AddEntry.route)
                    },
                    onSync = {
                        navController.navigate(Screen.Sync.route)
                    },
                    onSettings = {
                        navController.navigate(Screen.Settings.route)
                    },
                    onLock = {
                        isUnlocked = false
                        navController.navigate(Screen.Lock.route) {
                            popUpTo(0) { inclusive = true }
                        }
                    }
                )
            }
            
            composable(Screen.Entry.route) { backStackEntry ->
                val entryId = backStackEntry.arguments?.getString("entryId") ?: ""
                EntryDetailScreen(
                    entryId = entryId,
                    onBack = { navController.popBackStack() },
                    onDelete = { navController.popBackStack() },
                    onSave = { _, _, _, _ -> navController.popBackStack() }
                )
            }
            
            composable(Screen.AddEntry.route) {
                AddEntryScreen(
                    onBack = { navController.popBackStack() },
                    onSave = { _, _, _, _ ->
                        navController.popBackStack()
                    }
                )
            }
            
            composable(Screen.Settings.route) {
                SettingsScreen(
                    onBack = { navController.popBackStack() },
                    onBiometricToggle = { },
                    onAutoLockChange = { },
                    onPasskeySetup = { },
                    onManualSync = {
                        // Trigger manual sync via native
                    }
                )
            }
            
            composable(Screen.Sync.route) {
                P2PSyncScreen(
                    onBack = { navController.popBackStack() },
                    onStartSync = { }
                )
            }
        }
    }
}