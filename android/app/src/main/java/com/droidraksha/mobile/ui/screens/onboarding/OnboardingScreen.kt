package com.droidraksha.mobile.ui.screens.onboarding

import android.content.Intent
import android.provider.Settings
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.droidraksha.mobile.ui.theme.*

@Composable
fun OnboardingScreen(
    onAcceptAndContinue: () -> Unit
) {
    val context = LocalContext.current
    val scrollState = rememberScrollState()

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(ShieldNavyDark)
            .padding(24.dp)
            .verticalScroll(scrollState),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.SpaceBetween
    ) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Spacer(modifier = Modifier.height(32.dp))

            // Shield Icon Header
            Box(
                modifier = Modifier
                    .size(80.dp)
                    .clip(RoundedCornerShape(20.dp))
                    .background(ShieldNavyCard)
                    .border(2.dp, ShieldCyan, RoundedCornerShape(20.dp)),
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    imageVector = Icons.Default.Shield,
                    contentDescription = null,
                    tint = ShieldCyan,
                    modifier = Modifier.size(44.dp)
                )
            }

            Spacer(modifier = Modifier.height(20.dp))

            Text(
                text = "DroidRaksha Mobile",
                color = TextPrimary,
                fontSize = 24.sp,
                fontWeight = FontWeight.Bold
            )

            Text(
                text = "On-Device Threat Intelligence for Indian Smartphones",
                color = TextSecondary,
                fontSize = 13.sp,
                textAlign = TextAlign.Center,
                modifier = Modifier.padding(top = 4.dp)
            )

            Spacer(modifier = Modifier.height(24.dp))

            // Privacy & Consent Card
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(16.dp))
                    .background(ShieldNavyCard)
                    .border(1.dp, ShieldNavyBorder, RoundedCornerShape(16.dp))
                    .padding(18.dp)
            ) {
                Column {
                    Text(
                        text = "🔒 Privacy & Transparency Guarantee",
                        color = ShieldCyan,
                        fontSize = 14.sp,
                        fontWeight = FontWeight.Bold
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        text = "DroidRaksha operates on-device. Your photos, private messages, personal contacts, and browsing history are never uploaded or inspected.",
                        color = TextSecondary,
                        fontSize = 12.sp,
                        lineHeight = 18.sp
                    )
                }
            }

            Spacer(modifier = Modifier.height(20.dp))

            // Required Permissions Breakdown
            PermissionItem(
                icon = Icons.Default.Apps,
                title = "App Inventory (QUERY_ALL_PACKAGES)",
                description = "Scans installed app package names, APK signatures, and permissions to identify trojans and fake apps."
            )

            Spacer(modifier = Modifier.height(12.dp))

            PermissionItem(
                icon = Icons.Default.NetworkCheck,
                title = "Network Visibility (Usage Stats)",
                description = "Monitors background network bytes and connection regularity (CoV) to detect C2 bot beaconing."
            )

            Spacer(modifier = Modifier.height(12.dp))

            PermissionItem(
                icon = Icons.Default.Psychology,
                title = "On-Device AI / ONNX ML",
                description = "Executes local XGBoost and Isolation Forest models fully offline with zero battery drain."
            )
        }

        Column(
            modifier = Modifier.fillMaxWidth().padding(top = 28.dp)
        ) {
            Button(
                onClick = onAcceptAndContinue,
                colors = ButtonDefaults.buttonColors(containerColor = ShieldCyan),
                shape = RoundedCornerShape(12.dp),
                modifier = Modifier
                    .fillMaxWidth()
                    .height(52.dp)
            ) {
                Text(
                    text = "Grant Consent & Start Scan",
                    color = ShieldNavyDark,
                    fontSize = 15.sp,
                    fontWeight = FontWeight.Bold
                )
            }
            Spacer(modifier = Modifier.height(12.dp))
        }
    }
}

@Composable
private fun PermissionItem(
    icon: ImageVector,
    title: String,
    description: String
) {
    Row(
        verticalAlignment = Alignment.Top,
        modifier = Modifier.fillMaxWidth()
    ) {
        Box(
            modifier = Modifier
                .size(36.dp)
                .clip(RoundedCornerShape(8.dp))
                .background(ShieldNavyCard),
            contentAlignment = Alignment.Center
        ) {
            Icon(imageVector = icon, contentDescription = null, tint = ShieldCyan, modifier = Modifier.size(20.dp))
        }
        Spacer(modifier = Modifier.width(12.dp))
        Column {
            Text(text = title, color = TextPrimary, fontSize = 13.sp, fontWeight = FontWeight.SemiBold)
            Text(text = description, color = TextMuted, fontSize = 11.sp, lineHeight = 16.sp)
        }
    }
}
