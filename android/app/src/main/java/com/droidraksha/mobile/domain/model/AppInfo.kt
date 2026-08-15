package com.droidraksha.mobile.domain.model

/**
 * Canonical domain model for an installed application and its computed risk assessment.
 *
 * This is the primary data class flowing from the scan engines through
 * the repository into ViewModels and Compose screens. It is a pure Kotlin
 * data class with no Android framework dependencies so it can be unit-tested
 * without an Android runtime.
 */
data class AppInfo(
    val packageName: String,
    val appName: String,
    val versionName: String,
    val versionCode: Long,
    val installedAt: Long,
    val lastUpdated: Long,
    val apkSizeBytes: Long,
    val targetSdkVersion: Int,
    val minSdkVersion: Int,
    val installSource: InstallSource,

    // Certificate analysis
    val certIssuer: String,
    val certSubject: String,
    val isSelfSigned: Boolean,
    val isDebugCert: Boolean,

    // Risk assessment
    val riskScore: Int,
    val riskLevel: RiskLevel,
    val threatCategories: List<String>,

    // India-IOC findings
    val isFakeUpi: Boolean,
    val isFakeBank: Boolean,
    val isLoanScam: Boolean,
    val matchedIocDomains: List<String>,

    // Permission analysis
    val dangerousPermissions: List<String>,
    val dangerousComboFlags: List<String>,
    val totalPermissionCount: Int,

    // C2 signals
    val c2Verdict: C2Verdict,
    val c2ConfidenceScore: Int,
    val detectedC2Frameworks: List<String>,

    // ML inference
    val onnxPredictedClass: String,
    val onnxConfidence: Float,
    val isAnomalyFlagged: Boolean,

    val lastScannedAt: Long,
    val deepScanAvailable: Boolean,
)

enum class RiskLevel(val label: String, val score: Int) {
    SAFE("Safe", 0),
    LOW("Low", 20),
    MEDIUM("Medium", 40),
    HIGH("High", 60),
    CRITICAL("Critical", 80);

    companion object {
        fun fromScore(score: Int): RiskLevel = when {
            score >= 80 -> CRITICAL
            score >= 60 -> HIGH
            score >= 40 -> MEDIUM
            score >= 20 -> LOW
            else -> SAFE
        }

        fun fromString(value: String): RiskLevel =
            entries.find { it.name == value } ?: SAFE
    }
}

enum class InstallSource(val label: String) {
    PLAY_STORE("Google Play Store"),
    SIDELOADED("Sideloaded (Unknown Source)"),
    ADB("ADB / Developer Install"),
    UNKNOWN("Unknown");

    companion object {
        fun fromString(value: String): InstallSource =
            entries.find { it.name == value.uppercase() } ?: UNKNOWN
    }
}

enum class C2Verdict(val label: String) {
    NONE("None"),
    SUSPECTED("Suspected"),
    LIKELY("Likely C2"),
    CONFIRMED("Confirmed C2");

    companion object {
        fun fromString(value: String): C2Verdict =
            entries.find { it.name == value.uppercase() } ?: NONE
    }
}
