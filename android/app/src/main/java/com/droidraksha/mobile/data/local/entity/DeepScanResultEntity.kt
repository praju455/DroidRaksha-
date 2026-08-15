package com.droidraksha.mobile.data.local.entity

import androidx.room.Entity
import androidx.room.PrimaryKey

/**
 * Caches the result of an on-demand backend deep-scan for a specific app.
 * Only populated for MEDIUM+ risk apps that the user explicitly requests
 * deep analysis on. Contains the Gemini AI narrative and multi-source
 * threat intelligence verdict.
 */
@Entity(tableName = "deep_scan_results")
data class DeepScanResultEntity(
    @PrimaryKey
    val packageName: String,

    val fetchedAt: Long,                     // epoch millis

    // Threat intel aggregated verdict
    val virusTotalDetections: Int,
    val virusTotalTotalEngines: Int,
    val abuseIpdbMaxConfidence: Int,
    val otxIndicatorCount: Int,

    // MalBERT classification
    val malBertLabel: String,                // e.g. "Banking Trojan"
    val malBertConfidence: Float,

    // C2 verdict from backend
    val backendC2Verdict: String,            // NONE | SUSPECTED | LIKELY | CONFIRMED
    val confirmedC2IpCount: Int,
    val detectedFrameworks: String,          // JSON array of framework names

    // Gemini AI narrative (plain-English explanation for the user)
    val aiNarrativeSummary: String,
    val aiRecommendedAction: String,         // "UNINSTALL" | "RESTRICT" | "MONITOR" | "IGNORE"
    val aiActionDetail: String,              // Human-readable explanation of recommended action

    // Overall backend risk
    val backendRiskScore: Int,
    val backendRiskLevel: String,
)
