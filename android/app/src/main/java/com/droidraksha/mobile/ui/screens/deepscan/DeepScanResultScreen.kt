package com.droidraksha.mobile.ui.screens.deepscan

import android.content.Intent
import android.net.Uri
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.droidraksha.mobile.domain.model.RiskLevel
import com.droidraksha.mobile.ui.components.RiskBadge
import com.droidraksha.mobile.ui.theme.*

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DeepScanResultScreen(
    packageName: String,
    viewModel: DeepScanViewModel,
    onNavigateBack: () -> Unit,
) {
    val state by viewModel.uiState.collectAsState()
    val context = LocalContext.current

    LaunchedEffect(packageName) {
        viewModel.triggerDeepScan(packageName)
    }

    Scaffold(
        containerColor = ShieldNavyDark,
        topBar = {
            TopAppBar(
                title = { Text("Gemini AI Deep Scan", color = TextPrimary, fontSize = 18.sp, fontWeight = FontWeight.Bold) },
                navigationIcon = {
                    IconButton(onClick = onNavigateBack) {
                        Icon(Icons.Default.ArrowBack, contentDescription = "Back", tint = TextPrimary)
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = ShieldNavyDark)
            )
        }
    ) { innerPadding ->
        if (state.isLoading) {
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(innerPadding),
                contentAlignment = Alignment.Center
            ) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    CircularProgressIndicator(color = ShieldCyan)
                    Spacer(modifier = Modifier.height(16.dp))
                    Text(
                        text = "Querying Threat Intelligence & MalBERT...",
                        color = TextSecondary,
                        fontSize = 13.sp
                    )
                    Text(
                        text = "Synthesizing AI Forensic Verdict",
                        color = TextMuted,
                        fontSize = 11.sp
                    )
                }
            }
        } else {
            val result = state.result
            if (result != null) {
                LazyColumn(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(innerPadding)
                        .padding(horizontal = 20.dp),
                    verticalArrangement = Arrangement.spacedBy(16.dp)
                ) {
                    // Header Verdict Card
                    item {
                        Box(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clip(RoundedCornerShape(16.dp))
                                .background(ShieldNavyCard)
                                .border(1.dp, RiskCritical.copy(alpha = 0.5f), RoundedCornerShape(16.dp))
                                .padding(18.dp)
                        ) {
                            Column {
                                Row(
                                    verticalAlignment = Alignment.CenterVertically,
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    modifier = Modifier.fillMaxWidth()
                                ) {
                                    Column(modifier = Modifier.weight(1f)) {
                                        Text(state.appName, color = TextPrimary, fontSize = 18.sp, fontWeight = FontWeight.Bold)
                                        Text(result.packageName, color = TextMuted, fontSize = 11.sp)
                                    }
                                    RiskBadge(
                                        level = RiskLevel.fromString(result.backendRiskLevel),
                                        score = result.backendRiskScore
                                    )
                                }

                                Spacer(modifier = Modifier.height(12.dp))
                                Text(
                                    text = "Verdict: ${result.backendC2Verdict}",
                                    color = if (result.backendC2Verdict == "CONFIRMED") RiskCritical else RiskHigh,
                                    fontWeight = FontWeight.Bold,
                                    fontSize = 14.sp
                                )
                            }
                        }
                    }

                    // Gemini AI Narrative
                    item {
                        Box(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clip(RoundedCornerShape(16.dp))
                                .background(ShieldNavyCard)
                                .border(1.dp, ShieldCyan.copy(alpha = 0.4f), RoundedCornerShape(16.dp))
                                .padding(18.dp)
                        ) {
                            Column {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Icon(Icons.Default.AutoAwesome, contentDescription = null, tint = ShieldCyan, modifier = Modifier.size(18.dp))
                                    Spacer(modifier = Modifier.width(8.dp))
                                    Text("Gemini Security Copilot Analysis", color = ShieldCyan, fontSize = 14.sp, fontWeight = FontWeight.Bold)
                                }
                                Spacer(modifier = Modifier.height(10.dp))
                                Text(
                                    text = result.aiNarrativeSummary,
                                    color = TextPrimary,
                                    fontSize = 13.sp,
                                    lineHeight = 20.sp
                                )
                            }
                        }
                    }

                    // Multi-Source Threat Intel Cross-Check
                    item {
                        Box(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clip(RoundedCornerShape(16.dp))
                                .background(ShieldNavyCard)
                                .border(0.5.dp, ShieldNavyBorder, RoundedCornerShape(16.dp))
                                .padding(16.dp)
                        ) {
                            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                                Text("Global Threat Feeds Cross-Check", color = TextPrimary, fontSize = 14.sp, fontWeight = FontWeight.SemiBold)

                                Row(horizontalArrangement = Arrangement.SpaceBetween, modifier = Modifier.fillMaxWidth()) {
                                    Text("VirusTotal Hash Lookup:", color = TextSecondary, fontSize = 12.sp)
                                    Text("${result.virusTotalDetections} / ${result.virusTotalTotalEngines} engines", color = if (result.virusTotalDetections > 0) RiskCritical else RiskLow, fontWeight = FontWeight.Bold, fontSize = 12.sp)
                                }

                                Row(horizontalArrangement = Arrangement.SpaceBetween, modifier = Modifier.fillMaxWidth()) {
                                    Text("AbuseIPDB C2 Confidence:", color = TextSecondary, fontSize = 12.sp)
                                    Text("${result.abuseIpdbMaxConfidence}%", color = if (result.abuseIpdbMaxConfidence > 50) RiskHigh else RiskLow, fontWeight = FontWeight.Bold, fontSize = 12.sp)
                                }

                                Row(horizontalArrangement = Arrangement.SpaceBetween, modifier = Modifier.fillMaxWidth()) {
                                    Text("MalBERT Zero-Shot NLP:", color = TextSecondary, fontSize = 12.sp)
                                    Text(result.malBertLabel, color = ShieldCyan, fontWeight = FontWeight.Bold, fontSize = 12.sp)
                                }
                            }
                        }
                    }

                    // Recommended Action Button
                    item {
                        Button(
                            onClick = {
                                val uninstallIntent = Intent(Intent.ACTION_DELETE).apply {
                                    data = Uri.parse("package:${result.packageName}")
                                }
                                context.startActivity(uninstallIntent)
                            },
                            colors = ButtonDefaults.buttonColors(containerColor = RiskCritical),
                            shape = RoundedCornerShape(12.dp),
                            modifier = Modifier.fillMaxWidth().height(48.dp)
                        ) {
                            Icon(Icons.Default.DeleteForever, contentDescription = null, tint = TextPrimary)
                            Spacer(modifier = Modifier.width(8.dp))
                            Text("Uninstall Malicious App Immediately", color = TextPrimary, fontWeight = FontWeight.Bold)
                        }
                    }

                    item { Spacer(modifier = Modifier.height(24.dp)) }
                }
            }
        }
    }
}
