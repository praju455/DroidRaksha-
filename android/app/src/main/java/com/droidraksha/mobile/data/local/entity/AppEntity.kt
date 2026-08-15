package com.droidraksha.mobile.data.local.entity

import androidx.room.Entity
import androidx.room.PrimaryKey

/**
 * Persists metadata and last-computed risk score for every installed app on the device.
 * Updated on each scan cycle. Records whether the app is sideloaded (not from Play Store),
 * its declared dangerous permissions, and top C2/IOC flags from the analysis engines.
 */
@Entity(tableName = "apps")
data class AppEntity(
    @PrimaryKey
    val packageName: String,

    // App metadata
    val appName: String,
    val versionName: String,
    val versionCode: Long,
    val installedAt: Long,           // epoch millis
    val lastUpdated: Long,           // epoch millis
    val apkSizeBytes: Long,
    val targetSdkVersion: Int,
    val minSdkVersion: Int,
    val installSource: String,       // "play_store" | "sideloaded" | "adb" | "unknown"

    // Certificate
    val certIssuer: String,
    val certSubject: String,
    val isSelfSigned: Boolean,
    val isDebugCert: Boolean,

    // Risk scoring (from LocalRiskScorer)
    val riskScore: Int,              // 0–100
    val riskLevel: String,           // SAFE | LOW | MEDIUM | HIGH | CRITICAL
    val threatCategories: String,    // JSON array of threat category strings

    // India-IOC flags
    val isFakeUpi: Boolean,
    val isFakeBank: Boolean,
    val isLoanScam: Boolean,
    val matchedIocDomains: String,   // JSON array

    // Permission analysis
    val dangerousPermissions: String,    // JSON array of dangerous permission names
    val dangerousComboFlags: String,     // JSON array of combo flag descriptions
    val totalPermissionCount: Int,

    // C2 signals
    val c2Verdict: String,           // NONE | SUSPECTED | LIKELY | CONFIRMED
    val c2ConfidenceScore: Int,
    val detectedC2Frameworks: String,// JSON array

    // ML inference
    val onnxPredictedClass: String,  // Adware | Banking | SMS_Malware | Riskware | Benign
    val onnxConfidence: Float,
    val isAnomalyFlagged: Boolean,   // Isolation Forest anomaly flag

    // Scan metadata
    val lastScannedAt: Long,         // epoch millis of most recent full scan
    val deepScanAvailable: Boolean,  // True if backend deep-scan result is cached
)
