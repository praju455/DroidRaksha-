package com.droidraksha.mobile.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.droidraksha.mobile.domain.model.RiskLevel
import com.droidraksha.mobile.ui.theme.*

@Composable
fun RiskBadge(
    level: RiskLevel,
    score: Int? = null,
    modifier: Modifier = Modifier
) {
    val (color, bg) = when (level) {
        RiskLevel.CRITICAL -> Pair(RiskCritical, RiskCriticalBg)
        RiskLevel.HIGH -> Pair(RiskHigh, RiskHighBg)
        RiskLevel.MEDIUM -> Pair(RiskMedium, RiskMediumBg)
        RiskLevel.LOW -> Pair(RiskLow, RiskLowBg)
        RiskLevel.SAFE -> Pair(RiskSafe, RiskSafeBg)
    }

    Box(
        modifier = modifier
            .clip(RoundedCornerShape(8.dp))
            .background(bg)
            .border(1.dp, color.copy(alpha = 0.6f), RoundedCornerShape(8.dp))
            .padding(horizontal = 8.dp, vertical = 4.dp)
    ) {
        val label = if (score != null) "${level.label} ($score)" else level.label
        Text(
            text = label,
            color = color,
            fontSize = 11.sp,
            fontWeight = FontWeight.Bold
        )
    }
}

@Composable
fun ThreatChip(
    text: String,
    isWarning: Boolean = true,
    modifier: Modifier = Modifier
) {
    val color = if (isWarning) RiskHigh else ShieldCyan
    val bg = if (isWarning) RiskHighBg else ShieldNavyBorder

    Box(
        modifier = modifier
            .clip(RoundedCornerShape(6.dp))
            .background(bg)
            .border(0.5.dp, color.copy(alpha = 0.4f), RoundedCornerShape(6.dp))
            .padding(horizontal = 6.dp, vertical = 2.dp)
    ) {
        Text(
            text = text,
            color = color,
            fontSize = 10.sp,
            fontWeight = FontWeight.Medium
        )
    }
}
