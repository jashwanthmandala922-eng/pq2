package com.securevault.ui.theme

import android.app.Activity
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.SideEffect
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.platform.LocalView
import androidx.core.view.WindowCompat

// Glassmorphism Color Palette
object GlassColors {
    // Primary - Deep Blue
    val Primary = Color(0xFF2563EB)
    val PrimaryLight = Color(0xFF3B82F6)
    val PrimaryDark = Color(0xFF1D4ED8)
    
    // Secondary - Teal
    val Secondary = Color(0xFF14B8A6)
    val SecondaryLight = Color(0xFF2DD4BF)
    val SecondaryDark = Color(0xFF0D9488)
    
    // Accent - Purple
    val Accent = Color(0xFF8B5CF6)
    val AccentLight = Color(0xFFA78BFA)
    val AccentDark = Color(0xFF7C3AED)
    
    // Background - Glass
    val GlassBackground = Color(0xFFF8FAFC)
    val GlassBackgroundDark = Color(0xFF0F172A)
    
    // Surface - Glass effect
    val GlassSurface = Color(0xFFFFFFFF)
    val GlassSurfaceDark = Color(0xFF1E293B)
    
    // Glass overlay with transparency
    val GlassOverlay = Color(0x1AFFFFFF)
    val GlassOverlayDark = Color(0x1A000000)
    
    // Card glass effect
    val GlassCard = Color(0xB3FFFFFF)
    val GlassCardDark = Color(0x991E293B)
    
    // Text
    val TextPrimary = Color(0xFF0F172A)
    val TextPrimaryDark = Color(0xFFF8FAFC)
    val TextSecondary = Color(0xFF64748B)
    val TextSecondaryDark = Color(0xFF94A3B8)
    
    // Error
    val Error = Color(0xFFEF4444)
    val Success = Color(0xFF22C55E)
    val Warning = Color(0xFFF59E0B)
    
    // Gradient colors
    val GradientStart = Color(0xFF2563EB)
    val GradientEnd = Color(0xFF8B5CF6)
    
    // Glow
    val GlowBlue = Color(0xFF3B82F6)
    val GlowPurple = Color(0xFF8B5CF6)
}

private val DarkColorScheme = darkColorScheme(
    primary = GlassColors.PrimaryLight,
    onPrimary = Color.White,
    primaryContainer = GlassColors.PrimaryDark,
    onPrimaryContainer = Color.White,
    secondary = GlassColors.SecondaryLight,
    onSecondary = Color.White,
    secondaryContainer = GlassColors.SecondaryDark,
    onSecondaryContainer = Color.White,
    tertiary = GlassColors.AccentLight,
    onTertiary = Color.White,
    tertiaryContainer = GlassColors.AccentDark,
    onTertiaryContainer = Color.White,
    error = GlassColors.Error,
    onError = Color.White,
    background = GlassColors.GlassBackgroundDark,
    onBackground = GlassColors.TextPrimaryDark,
    surface = GlassColors.GlassSurfaceDark,
    onSurface = GlassColors.TextPrimaryDark,
    surfaceVariant = GlassColors.GlassCardDark,
    onSurfaceVariant = GlassColors.TextSecondaryDark,
    outline = GlassColors.TextSecondaryDark,
    outlineVariant = GlassColors.GlassOverlayDark,
)

private val LightColorScheme = lightColorScheme(
    primary = GlassColors.Primary,
    onPrimary = Color.White,
    primaryContainer = GlassColors.PrimaryLight,
    onPrimaryContainer = Color.White,
    secondary = GlassColors.Secondary,
    onSecondary = Color.White,
    secondaryContainer = GlassColors.SecondaryLight,
    onSecondaryContainer = Color.White,
    tertiary = GlassColors.Accent,
    onTertiary = Color.White,
    tertiaryContainer = GlassColors.AccentLight,
    onTertiaryContainer = Color.White,
    error = GlassColors.Error,
    onError = Color.White,
    background = GlassColors.GlassBackground,
    onBackground = GlassColors.TextPrimary,
    surface = GlassColors.GlassSurface,
    onSurface = GlassColors.TextPrimary,
    surfaceVariant = GlassColors.GlassCard,
    onSurfaceVariant = GlassColors.TextSecondary,
    outline = GlassColors.TextSecondary,
    outlineVariant = GlassColors.GlassOverlay,
)

@Composable
fun SecureVaultTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit
) {
    val colorScheme = if (darkTheme) DarkColorScheme else LightColorScheme
    
    val view = LocalView.current
    if (!view.isInEditModeColors) {
        SideEffect {
            val window = (view.context as Activity).window
            window.statusBarColor = colorScheme.background.toArgb()
            window.navigationBarColor = colorScheme.background.toArgb()
            WindowCompat.getInsetsController(window, view).apply {
                isAppearanceLightStatusBars = !darkTheme
                isAppearanceLightNavigationBars = !darkTheme
            }
        }
    }
    
    MaterialTheme(
        colorScheme = colorScheme,
        typography = Typography,
        content = content
    )
}