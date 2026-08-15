package com.droidraksha.mobile.ui.screens.appdetail

import android.content.Intent
import android.net.Uri
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
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
import com.droidraksha.mobile.domain.model.C2Verdict
import com.droidraksha.mobile.domain.model.RiskLevel
import com.droidraksha.mobile.ui.components.RiskBadge
import com.droidraksha.mobile.ui.components.ThreatChip
import com.droidraksha.mobile.ui.theme.*

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AppDetailScreen(
    packageName: String,
    viewModel: AppDetailViewModel,
    onNavigateBack: () -> Unit,
    onNavigateToDeepScan: (String) -> Unit,
) {
    val state by viewModel.uiState.collectAsState()
    val context = LocalContext.current

    LaunchedEffect(packageName) {
        viewModel.loadApp(packageName)
    }

    Scaffold(
        containerColor = ShieldNavyDark,
        topBar = {
            TopAppBar(
                title = { Text("Forensic Detail", color = TextPrimary, fontSize = 18.sp, fontWeight = FontWeight.Bold) },
                navigationIcon = {
                    IconButton(onClick = onNavigateBack) {
                        Icon(Icons.Default.ArrowBack, contentDescription = "Back", tint = TextPrimary)
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = ShieldNavyDark)
            )
        }
    ) { innerPadding ->
        val app = state.app
        if (app == null) {
            Box(modifier = Modifier.fillMaxSize().padding(innerPadding), contentAlignment = Alignment.Center) {
                CircularProgressIndicator(color = ShieldCyan)
            }
        } else {
            LazyColumn(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(innerPadding)
                    .padding(horizontal = 20.dp),
                verticalArrangement = Arrangement.spacedBy(16.dp)
            ) {
                // Header Card
                item {
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(16.dp))
                            .background(ShieldNavyCard)
                            .border(1.dp, ShieldNavyBorder, RoundedCornerShape(16.dp))
                            .padding(18.dp)
                    ) {
                        Column {
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.SpaceBetween,
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(app.appName, color = TextPrimary, fontSize = 18.sp, fontWeight = FontWeight.Bold)
                                    Text(app.packageName, color = TextMuted, fontSize = 12.sp)
                                }
                                RiskBadge(level = app.riskLevel, score = app.riskScore)
                            }

                            Spacer(modifier = Modifier.height(14.dp))
                            Divider(color = ShieldNavyBorder, thickness = 0.5.dp)
                            Spacer(modifier = Modifier.height(14.dp))

                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween
                            ) {
                                InfoPill("Source", app.installSource.label)
                                InfoPill("Version", app.versionName)
                                InfoPill("Size", "${app.apkSizeBytes / 1024 / 1024} MB")
                            }
                        }
                    }
                }

                // C2 & Network Beacon Status
                item {
                    DetailSectionCard(title = "📡 C2 Infrastructure & Network Beaconing") {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.SpaceBetween,
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Text("C2 Verdict:", color = TextSecondary, fontSize = 13.sp)
                            val c2Color = when (app.c2Verdict) {
                                C2Verdict.CONFIRMED -> RiskCritical
                                C2Verdict.LIKELY -> RiskHigh
                                C2Verdict.SUSPECTED -> RiskMedium
                                C2Verdict.NONE -> RiskLow
                            }
                            Text(app.c2Verdict.label, color = c2Color, fontWeight = FontWeight.Bold, fontSize = 13.sp)
                        }

                        if (app.detectedC2Frameworks.isNotEmpty()) {
                            Spacer(modifier = Modifier.height(8.dp))
                            Text("Detected C2 Frameworks:", color = TextSecondary, fontSize = 12.sp)
                            Spacer(modifier = Modifier.height(4.dp))
                            Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                                app.detectedC2Frameworks.forEach { fw ->
                                    ThreatChip(text = fw, isWarning = true)
                                }
                            }
                        }
                    }
                }

                // India-IOC Findings Card
                item {
                    DetailSectionCard(title = "🇮🇳 India Threat Intelligence Matches") {
                        if (!app.isFakeUpi && !app.isFakeBank && !app.isLoanScam && app.matchedIocDomains.isEmpty()) {
                            Text("No Indian fraud/phishing signatures matched.", color = RiskLow, fontSize = 12.sp)
                        } else {
                            if (app.isFakeUpi) ThreatFlagRow("⚠️ Fake UPI / NPCI Impersonation signature matched")
                            if (app.isFakeBank) ThreatFlagRow("⚠️ Fake Indian Banking Login / Domain match")
                            if (app.isLoanScam) ThreatFlagRow("⚠️ Predatory Instant Loan / Blackmail pattern")
                            app.matchedIocDomains.forEach { domain ->
                                ThreatFlagRow("🔗 Fraud domain: $domain")
                            }
                        }
                    }
                }

                // Dangerous Permissions & Combos
                item {
                    DetailSectionCard(title = "🔐 Dangerous Permissions & Combos") {
                        if (app.dangerousComboFlags.isEmpty() && app.dangerousPermissions.isEmpty()) {
                            Text("No high-risk permission combinations held.", color = RiskLow, fontSize = 12.sp)
                        } else {
                            app.dangerousComboFlags.forEach { combo ->
                                ThreatFlagRow("⚡ $combo")
                                Spacer(modifier = Modifier.height(4.dp))
                            }
                            if (app.dangerousPermissions.isNotEmpty()) {
                                Spacer(modifier = Modifier.height(8.dp))
                                Text("Held Permissions (${app.dangerousPermissions.size}):", color = TextSecondary, fontSize = 12.sp)
                                Spacer(modifier = Modifier.height(4.dp))
                                app.dangerousPermissions.forEach { perm ->
                                    Text("• ${perm.removePrefix("android.permission.")}", color = TextMuted, fontSize = 11.sp)
                                }
                            }
                        }
                    }
                }

                // On-Device ML Inference (ONNX)
                item {
                    DetailSectionCard(title = "🧠 On-Device ML (XGBoost + Isolation Forest)") {
                        Row(
                            horizontalArrangement = Arrangement.SpaceBetween,
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Text("XGBoost Class:", color = TextSecondary, fontSize = 13.sp)
                            Text(app.onnxPredictedClass, color = if (app.onnxPredictedClass == "Benign") RiskLow else RiskHigh, fontWeight = FontWeight.Bold, fontSize = 13.sp)
                        }
                        Spacer(modifier = Modifier.height(6.dp))
                        Row(
                            horizontalArrangement = Arrangement.SpaceBetween,
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Text("Anomaly (Zero-Day):", color = TextSecondary, fontSize = 13.sp)
                            Text(if (app.isAnomalyFlagged) "Flagged (Unusual)" else "Normal", color = if (app.isAnomalyFlagged) RiskHigh else RiskLow, fontWeight = FontWeight.SemiBold, fontSize = 13.sp)
                        }
                    }
                }

                // Actions Card
                item {
                    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                        // AI Deep Scan (if Medium+)
                        if (app.riskScore >= 40) {
                            Button(
                                onClick = { onNavigateToDeepScan(app.packageName) },
                                colors = ButtonDefaults.buttonColors(containerColor = ShieldCyan),
                                shape = RoundedCornerShape(12.dp),
                                modifier = Modifier.fillMaxWidth().height(48.dp)
                            ) {
                                Icon(Icons.Default.Psychology, contentDescription = null, tint = ShieldNavyDark)
                                Spacer(modifier = Modifier.width(8.dp))
                                Text("Run Gemini AI Deep Scan", color = ShieldNavyDark, fontWeight = FontWeight.Bold)
                            }
                        }

                        // Uninstall Button
                        OutlinedButton(
                            onClick = {
                                val uninstallIntent = Intent(Intent.ACTION_DELETE).apply {
                                    data = Uri.parse("package:${app.packageName}")
                                }
                                context.startActivity(uninstallIntent)
                            },
                            colors = ButtonDefaults.outlinedButtonColors(contentColor = RiskCritical),
                            border = ButtonDefaults.outlinedButtonBorder.copy(brush = androidx.compose.ui.graphics.SolidColor(RiskCritical)),
                            shape = RoundedCornerShape(12.dp),
                            modifier = Modifier.fillMaxWidth().height(48.dp)
                        ) {
                            Icon(Icons.Default.Delete, contentDescription = null, tint = RiskCritical)
                            Spacer(modifier = Modifier.width(8.dp))
                            Text("Uninstall Application", color = RiskCritical, fontWeight = FontWeight.Bold)
                        }
                    }
                }

                item { Spacer(modifier = Modifier.height(24.dp)) }
            }
        }
    }
}

@Composable
private fun InfoPill(label: String, value: String) {
    Column {
        Text(label, color = TextMuted, fontSize = 10.sp)
        Text(value, color = TextPrimary, fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
    }
}

@Composable
private fun DetailSectionCard(
    title: String,
    content: @Composable ColumnScope.() -> Unit
) {
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(14.dp))
            .background(ShieldNavyCard)
            .border(0.5.dp, ShieldNavyBorder, RoundedCornerShape(14.dp))
            .padding(16.dp)
    ) {
        Column {
            Text(title, color = TextPrimary, fontSize = 14.sp, fontWeight = FontWeight.SemiBold)
            Spacer(modifier = Modifier.height(10.dp))
            content()
        }
    }
}

@Composable
private fun ThreatFlagRow(text: String) {
    Text(text, color = RiskHigh, fontSize = 12.sp, lineHeight = 16.sp)
}
