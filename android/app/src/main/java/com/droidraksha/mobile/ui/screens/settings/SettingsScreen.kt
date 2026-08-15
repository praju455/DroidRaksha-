package com.droidraksha.mobile.ui.screens.settings

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.droidraksha.mobile.ui.theme.*

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(
    viewModel: SettingsViewModel,
    onNavigateBack: () -> Unit,
) {
    val state by viewModel.uiState.collectAsState()
    var urlInput by remember(state.backendUrl) { mutableStateOf(state.backendUrl) }

    Scaffold(
        containerColor = ShieldNavyDark,
        topBar = {
            TopAppBar(
                title = { Text("Settings & Intelligence Config", color = TextPrimary, fontSize = 18.sp, fontWeight = FontWeight.Bold) },
                navigationIcon = {
                    IconButton(onClick = onNavigateBack) {
                        Icon(Icons.Default.ArrowBack, contentDescription = "Back", tint = TextPrimary)
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = ShieldNavyDark)
            )
        }
    ) { innerPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .padding(horizontal = 20.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            // Background Scanner Toggle
            SettingCard {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text("Periodic Background Scan", color = TextPrimary, fontSize = 14.sp, fontWeight = FontWeight.SemiBold)
                        Text("Runs on-device WorkManager scan every 24h & on app installs", color = TextMuted, fontSize = 11.sp)
                    }
                    Switch(
                        checked = state.backgroundScanEnabled,
                        onCheckedChange = { viewModel.setBackgroundScan(it) },
                        colors = SwitchDefaults.colors(
                            checkedThumbColor = ShieldNavyDark,
                            checkedTrackColor = ShieldCyan,
                            uncheckedTrackColor = ShieldNavySurface
                        )
                    )
                }
            }

            // Wi-Fi Only Sync Toggle
            SettingCard {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text("Wi-Fi Only for Deep Scan", color = TextPrimary, fontSize = 14.sp, fontWeight = FontWeight.SemiBold)
                        Text("Prevent cellular data usage when uploading IOC hashes for deep scan", color = TextMuted, fontSize = 11.sp)
                    }
                    Switch(
                        checked = state.wifiOnlySync,
                        onCheckedChange = { viewModel.setWifiOnlySync(it) },
                        colors = SwitchDefaults.colors(
                            checkedThumbColor = ShieldNavyDark,
                            checkedTrackColor = ShieldCyan,
                            uncheckedTrackColor = ShieldNavySurface
                        )
                    )
                }
            }

            // Backend Endpoint Configuration
            SettingCard {
                Column {
                    Text("Slim Backend Endpoint (FastAPI)", color = TextPrimary, fontSize = 14.sp, fontWeight = FontWeight.SemiBold)
                    Text("Base URL used for on-demand /check-ioc AI deep scans", color = TextMuted, fontSize = 11.sp)
                    Spacer(modifier = Modifier.height(10.dp))
                    OutlinedTextField(
                        value = urlInput,
                        onValueChange = { urlInput = it },
                        singleLine = true,
                        shape = RoundedCornerShape(10.dp),
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedContainerColor = ShieldNavySurface,
                            unfocusedContainerColor = ShieldNavySurface,
                            focusedBorderColor = ShieldCyan,
                            unfocusedBorderColor = ShieldNavyBorder,
                            focusedTextColor = TextPrimary,
                            unfocusedTextColor = TextPrimary
                        ),
                        modifier = Modifier.fillMaxWidth()
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    Button(
                        onClick = { viewModel.updateBackendUrl(urlInput) },
                        colors = ButtonDefaults.buttonColors(containerColor = ShieldCyan),
                        shape = RoundedCornerShape(8.dp),
                        modifier = Modifier.align(Alignment.End)
                    ) {
                        Text("Save URL", color = ShieldNavyDark, fontSize = 12.sp, fontWeight = FontWeight.Bold)
                    }
                }
            }

            // About DroidRaksha Card
            SettingCard {
                Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text("DroidRaksha Mobile v1.0.0", color = TextPrimary, fontSize = 14.sp, fontWeight = FontWeight.Bold)
                    Text("Purpose-built for Smart India Hackathon (SIH260138)", color = ShieldCyan, fontSize = 12.sp)
                    Text("Ministry of Power · Blockchain & Cybersecurity", color = TextSecondary, fontSize = 11.sp)
                    Text("BMS Institute of Technology and Management", color = TextMuted, fontSize = 11.sp)
                }
            }

            Spacer(modifier = Modifier.height(20.dp))
        }
    }
}

@Composable
private fun SettingCard(content: @Composable ColumnScope.() -> Unit) {
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(14.dp))
            .background(ShieldNavyCard)
            .border(0.5.dp, ShieldNavyBorder, RoundedCornerShape(14.dp))
            .padding(16.dp)
    ) {
        Column { content() }
    }
}
