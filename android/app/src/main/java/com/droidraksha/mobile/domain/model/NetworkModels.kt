package com.droidraksha.mobile.domain.model

/**
 * Network traffic metrics collected from [NetworkStatsManager] for a single app.
 * Used by the App Detail screen and the C2BeaconDetector.
 */
data class NetworkMetrics(
    val packageName: String,
    val uid: Int,

    // Total traffic in the last 24 hours
    val rxBytesLast24h: Long,
    val txBytesLast24h: Long,

    // Background vs foreground breakdown
    val backgroundRxBytes: Long,
    val backgroundTxBytes: Long,
    val foregroundRxBytes: Long,
    val foregroundTxBytes: Long,

    // C2 beaconing signals
    val connectionIntervals: List<Long>,     // milliseconds between recorded connections
    val intervalCoefficientOfVariation: Float, // CoV — low CoV = regular = suspicious beaconing
    val isBeaconingFlagged: Boolean,         // CoV < 0.3 AND at least 5 intervals observed

    // Snapshot timestamp
    val capturedAt: Long,
)

/**
 * C2 signal emitted by the [C2BeaconDetector] for a specific app.
 */
data class C2Signal(
    val packageName: String,
    val verdictFromBeaconing: C2Verdict,
    val beaconingCoV: Float,
    val sampleIntervalCount: Int,
    val reason: String,
)

/**
 * Composite risk score computed by [LocalRiskScorer].
 */
data class RiskScore(
    val packageName: String,
    val totalScore: Int,                    // 0–100
    val riskLevel: RiskLevel,
    val breakdown: RiskBreakdown,
    val threatCategories: List<String>,
    val c2Verdict: C2Verdict,
)

/**
 * Score breakdown mirrors [backend/scoring/risk_scorer.py] logic.
 */
data class RiskBreakdown(
    val yaraLite: Int,          // 0–30: YARA-lite string pattern hits
    val indiaIoc: Int,          // 0–30: India-IOC matches (fake UPI/bank/discom)
    val c2Signals: Int,         // 0–40: C2 beaconing + confirmed framework patterns
    val permissions: Int,       // 0–10: dangerous permission combos
    val certificate: Int,       // 0–20: self-signed / debug cert penalty
    val onnxAnomaly: Int,       // 0–5:  Isolation Forest anomaly flag
    val sideloaded: Int,        // 0–3:  sideloaded APK penalty
)
