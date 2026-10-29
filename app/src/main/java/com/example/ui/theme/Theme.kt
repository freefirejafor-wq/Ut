package com.example.ui.theme

import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp

private val DarkColorScheme = darkColorScheme(
    primary = MatrixEmerald,
    onPrimary = MatrixEmeraldDark,
    primaryContainer = MatrixEmeraldContainer,
    onPrimaryContainer = MatrixEmerald,
    secondary = CyberCyan,
    onSecondary = CyberCyanDark,
    secondaryContainer = CyberCyanContainer,
    onSecondaryContainer = CyberCyan,
    tertiary = ForensicAmber,
    onTertiary = Color(0xFF1F1600),
    tertiaryContainer = ForensicAmberContainer,
    onTertiaryContainer = ForensicAmber,
    error = AlertCoral,
    onError = Color(0xFF2D060D),
    errorContainer = AlertCoralContainer,
    onErrorContainer = AlertCoral,
    background = ObsidianBackground,
    onBackground = TextPrimary,
    surface = ObsidianSurface,
    onSurface = TextPrimary,
    surfaceVariant = ObsidianSurfaceVariant,
    onSurfaceVariant = TextSecondary,
    surfaceContainerHigh = ObsidianContainerHigh,
    outline = ObsidianOutline,
    outlineVariant = Color(0xFF1A273D)
)

private val LightColorScheme = lightColorScheme(
    primary = EmeraldLightPrimary,
    onPrimary = Color.White,
    primaryContainer = Color(0xFFD1FAE5),
    onPrimaryContainer = Color(0xFF064E3B),
    secondary = CyanLightSecondary,
    onSecondary = Color.White,
    secondaryContainer = Color(0xFFE0F2FE),
    onSecondaryContainer = Color(0xFF0C4A6E),
    tertiary = AmberLightTertiary,
    onTertiary = Color.White,
    tertiaryContainer = Color(0xFFFEF3C7),
    onTertiaryContainer = Color(0xFF78350F),
    background = SlateLightBackground,
    onBackground = Color(0xFF0F172A),
    surface = SlateLightSurface,
    onSurface = Color(0xFF0F172A),
    surfaceVariant = SlateLightSurfaceVariant,
    onSurfaceVariant = Color(0xFF475569),
    outline = Color(0xFFCBD5E1)
)

val AppShapes = Shapes(
    extraSmall = RoundedCornerShape(6.dp),
    small = RoundedCornerShape(10.dp),
    medium = RoundedCornerShape(14.dp),
    large = RoundedCornerShape(18.dp),
    extraLarge = RoundedCornerShape(24.dp)
)

@Composable
fun MyApplicationTheme(
    darkTheme: Boolean = true, // Default to forensic dark mode
    dynamicColor: Boolean = false,
    content: @Composable () -> Unit,
) {
    val colorScheme = if (darkTheme) DarkColorScheme else LightColorScheme

    MaterialTheme(
        colorScheme = colorScheme,
        typography = Typography,
        shapes = AppShapes,
        content = content
    )
}
