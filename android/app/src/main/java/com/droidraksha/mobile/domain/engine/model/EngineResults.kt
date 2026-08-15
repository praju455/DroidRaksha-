package com.droidraksha.mobile.domain.engine.model

/**
 * Result of [PermissionComboAnalyzer.analyze] for a single package.
 */
data class PermissionAnalysisResult(
    val packageName: String,
    val dangerousPermissions: List<String>,
    val dangerousComboFlags: List<String>,
    val permissionRiskScore: Int,   // 0–10 (used as secondary signal)
    val totalPermissionCount: Int,
)

/**
 * Result of [IndiaIocMatcher.match] for a single package.
 */
data class IocMatchResult(
    val packageName: String,
    val isFakeUpi: Boolean,
    val isFakeBank: Boolean,
    val isLoanScam: Boolean,
    val isFakeDiscom: Boolean,
    val matchedPackages: List<String>,
    val matchedDomains: List<String>,
    val matchedIps: List<String>,
    val riskFlags: List<String>,
    val iocRiskScore: Int,           // 0–30 (used as primary signal)
)

/**
 * Result of [YaraLiteMatcher.scan] for a single package.
 */
data class YaraLiteResult(
    val packageName: String,
    val matches: List<YaraMatch>,
    val yaraRiskScore: Int,          // 0–30 (used as primary signal)
)

data class YaraMatch(
    val ruleName: String,
    val severity: String,           // CRITICAL | HIGH | MEDIUM | LOW
    val description: String,
    val matchedString: String,
)

/**
 * Result of [OnDeviceMLInference.classify] for a single package.
 */
data class OnnxInferenceResult(
    val packageName: String,
    val predictedClass: String,      // Adware | Banking | SMS_Malware | Riskware | Benign
    val confidence: Float,           // 0.0–1.0
    val isAnomalyFlagged: Boolean,   // Isolation Forest flag
    val classProbabilities: Map<String, Float>,
)
