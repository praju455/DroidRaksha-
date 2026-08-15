package com.droidraksha.mobile.ui.screens.dashboard

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.droidraksha.mobile.domain.model.RiskLevel
import com.droidraksha.mobile.ui.components.AppRowItem
import com.droidraksha.mobile.ui.components.StatCard
import com.droidraksha.mobile.ui.theme.*

@Composable
fun DashboardScreen(
    viewModel: DashboardViewModel,
    onNavigateToAppList: (String?) -> Unit,
    onNavigateToAppDetail: (String) -> Unit,
    onNavigateToHistory: () -> Unit,
    onNavigateToSettings: () -> Unit,
) {
    val state by viewModel.uiState.collectAsState()

    Scaffold(
        containerColor = ShieldNavyDark,
        topBar = {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 20.dp, vertical = 16.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        imageVector = Icons.Default.Security,
                        contentDescription = null,
                        tint = ShieldCyan,
                        modifier = Modifier.size(28.dp)
                    )
                    Spacer(modifier = Modifier.width(10.dp))
                    Text(
                        text = "DroidRaksha",
                        color = TextPrimary,
                        fontSize = 20.sp,
                        fontWeight = FontWeight.Bold
                    )
                }

                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    IconButton(onClick = onNavigateToHistory) {
                        Icon(Icons.Default.History, contentDescription = "History", tint = TextSecondary)
                    }
                    IconButton(onClick = onNavigateToSettings) {
                        Icon(Icons.Default.Settings, contentDescription = "Settings", tint = TextSecondary)
                    }
                }
            }
        }
    ) { innerPadding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .padding(horizontal = 20.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            // Scanning progress card (if active)
            if (state.isScanning) {
                item {
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(16.dp))
                            .background(ShieldNavyCard)
                            .border(1.dp, ShieldCyan, RoundedCornerShape(16.dp))
                            .padding(16.dp)
                    ) {
                        Column {
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.SpaceBetween,
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Text("Scanning Installed Apps...", color = ShieldCyan, fontWeight = FontWeight.Bold, fontSize = 14.sp)
                                Text("${state.scanProgress} / ${state.scanTotal}", color = TextSecondary, fontSize = 12.sp)
                            }
                            Spacer(modifier = Modifier.height(10.dp))
                            val progress = if (state.scanTotal > 0) state.scanProgress.toFloat() / state.scanTotal else 0f
                            LinearProgressIndicator(
                                progress = { progress },
                                modifier = Modifier.fillMaxWidth().height(6.dp).clip(RoundedCornerShape(3.dp)),
                                color = ShieldCyan,
                                trackColor = ShieldNavySurface,
                            )
                            Spacer(modifier = Modifier.height(6.dp))
                            Text(
                                text = state.currentScanningApp,
                                color = TextMuted,
                                fontSize = 11.sp,
                                maxLines = 1
                            )
                        }
                    }
                }
            }

            // Security Status Dial / Card
            item {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(20.dp))
                        .background(ShieldNavyCard)
                        .border(1.dp, ShieldNavyBorder, RoundedCornerShape(20.dp))
                        .padding(20.dp)
                ) {
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.SpaceBetween,
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Column {
                                Text("Device Threat Status", color = TextSecondary, fontSize = 13.sp)
                                val statusText = when {
                                    state.criticalCount > 0 -> "Critical Threats Detected"
                                    state.highCount > 0 -> "High Risk Apps Found"
                                    state.mediumCount > 0 -> "Medium Risk Warnings"
                                    else -> "Device Protected"
                                }
                                val statusColor = when {
                                    state.criticalCount > 0 -> RiskCritical
                                    state.highCount > 0 -> RiskHigh
                                    state.mediumCount > 0 -> RiskMedium
                                    else -> RiskLow
                                }
                                Text(statusText, color = statusColor, fontSize = 18.sp, fontWeight = FontWeight.Bold)
                            }

                            // Score Circle
                            Box(
                                modifier = Modifier
                                    .size(54.dp)
                                    .clip(CircleShape)
                                    .background(ShieldNavySurface)
                                    .border(2.dp, if (state.deviceRiskScore > 40) RiskHigh else ShieldCyan, CircleShape),
                                contentAlignment = Alignment.Center
                            ) {
                                Text(
                                    text = state.deviceRiskScore.toString(),
                                    color = TextPrimary,
                                    fontWeight = FontWeight.Bold,
                                    fontSize = 18.sp
                                )
                            }
                        }

                        Spacer(modifier = Modifier.height(18.dp))

                        // Quick Scan Button
                        Button(
                            onClick = { viewModel.startScan() },
                            enabled = !state.isScanning,
                            colors = ButtonDefaults.buttonColors(containerColor = ShieldCyan),
                            shape = RoundedCornerShape(12.dp),
                            modifier = Modifier.fillMaxWidth().height(46.dp)
                        ) {
                            Icon(Icons.Default.Refresh, contentDescription = null, tint = ShieldNavyDark)
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(
                                if (state.isScanning) "Scanning..." else "Run Security Scan",
                                color = ShieldNavyDark,
                                fontWeight = FontWeight.Bold
                            )
                        }
                    }
                }
            }

            // 5-Tier Summary Stats Grid
            item {
                Text("App Risk Breakdown", color = TextPrimary, fontSize = 15.sp, fontWeight = FontWeight.SemiBold)
                Spacer(modifier = Modifier.height(8.dp))
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    StatCard("Critical", state.criticalCount, RiskCritical, Icons.Default.Warning, onClick = { onNavigateToAppList("CRITICAL") }, modifier = Modifier.weight(1f))
                    StatCard("High", state.highCount, RiskHigh, Icons.Default.ErrorOutline, onClick = { onNavigateToAppList("HIGH") }, modifier = Modifier.weight(1f))
                    StatCard("Medium", state.mediumCount, RiskMedium, Icons.Default.Info, onClick = { onNavigateToAppList("MEDIUM") }, modifier = Modifier.weight(1f))
                }
                Spacer(modifier = Modifier.height(10.dp))
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    StatCard("Low Risk", state.lowCount, RiskLow, null, onClick = { onNavigateToAppList("LOW") }, modifier = Modifier.weight(1f))
                    StatCard("Safe Apps", state.safeCount, RiskSafe, Icons.Default.CheckCircle, onClick = { onNavigateToAppList("SAFE") }, modifier = Modifier.weight(1f))
                    StatCard("Total Scanned", state.totalApps, TextPrimary, Icons.Default.Apps, onClick = { onNavigateToAppList(null) }, modifier = Modifier.weight(1f))
                }
            }

            // Top Flagged Threats Section
            if (state.topThreats.isNotEmpty()) {
                item {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text("Top Action Required", color = TextPrimary, fontSize = 15.sp, fontWeight = FontWeight.SemiBold)
                        TextButton(onClick = { onNavigateToAppList(null) }) {
                            Text("View All (${state.totalApps})", color = ShieldCyan, fontSize = 12.sp)
                        }
                    }
                }

                items(state.topThreats) { app ->
                    AppRowItem(app = app, onClick = { onNavigateToAppDetail(app.packageName) })
                }
            }

            item { Spacer(modifier = Modifier.height(24.dp)) }
        }
    }
}
