package com.droidraksha.mobile.domain.engine

import com.droidraksha.mobile.domain.engine.model.IocMatchResult
import com.droidraksha.mobile.domain.engine.model.OnnxInferenceResult
import com.droidraksha.mobile.domain.engine.model.PermissionAnalysisResult
import com.droidraksha.mobile.domain.engine.model.YaraLiteResult
import com.droidraksha.mobile.domain.model.C2Signal
import com.droidraksha.mobile.domain.model.C2Verdict
import com.droidraksha.mobile.domain.model.RiskBreakdown
import com.droidraksha.mobile.domain.model.RiskLevel
import com.droidraksha.mobile.domain.model.RiskScore
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Layer 4 Engine — Local Risk Scorer.
 *
 * Aggregates all engine outputs into a single 0–100 risk score and maps
 * it to a [RiskLevel] tier. Logic is ported from
 * [backend/scoring/risk_scorer.py] and adapted for the on-device context.
 *
 * Scoring model:
 *   Primary signals (max 80 pts):
 *     - YARA-Lite hits:      0–30 pts
 *     - India-IOC matches:   0–30 pts
 *     - C2 signals:          0–40 pts (beaconing + framework + intel)
 *   Secondary signals (max 20 pts):
 *     - Permission combos:   0–10 pts
 *     - Certificate issues:  0–5 pts
 *     - ONNX anomaly flag:   0–5 pts (Isolation Forest)
 *     - Sideloaded APK:      0–3 pts
 *   Total = min(80, primary) + min(20, secondary), capped at 100.
 *
 * Risk Tiers:
 *   SAFE (0–19), LOW (20–39), MEDIUM (40–59), HIGH (60–79), CRITICAL (80–100)
 */
@Singleton
class LocalRiskScorer @Inject constructor() {

    fun score(
        packageName: String,
        yaraResult: YaraLiteResult,
        iocResult: IocMatchResult,
        c2Signal: C2Signal,
        permResult: PermissionAnalysisResult,
        onnxResult: OnnxInferenceResult,
        isSelfSigned: Boolean,
        isDebugCert: Boolean,
        installSource: String,
    ): RiskScore {

        // ── Primary signals ──────────────────────────────────────────────
        val yaraScore = yaraResult.yaraRiskScore.coerceIn(0, 30)
        val iocScore = iocResult.iocRiskScore.coerceIn(0, 30)
        val c2Score = computeC2Score(c2Signal).coerceIn(0, 40)
        val primaryScore = yaraScore + iocScore + c2Score

        // ── Secondary signals ────────────────────────────────────────────
        val permScore = permResult.permissionRiskScore.coerceIn(0, 10)

        val certScore = when {
            isDebugCert -> 5
            isSelfSigned -> 3
            else -> 0
        }.coerceIn(0, 5)

        val anomalyScore = if (onnxResult.isAnomalyFlagged) 5 else 0

        val sideloadScore = when (installSource.uppercase()) {
            "SIDELOADED", "ADB" -> 3
            else -> 0
        }

        val secondaryScore = permScore + certScore + anomalyScore + sideloadScore

        // ── Total with caps ──────────────────────────────────────────────
        val total = (primaryScore.coerceAtMost(80) + secondaryScore.coerceAtMost(20))
            .coerceIn(0, 100)

        val riskLevel = RiskLevel.fromScore(total)

        // ── Threat categories ────────────────────────────────────────────
        val categories = buildList {
            if (iocResult.isFakeUpi || iocResult.isFakeBank) add("Banking Trojan")
            if (iocResult.isLoanScam) add("Loan Scam")
            if (iocResult.isFakeDiscom) add("Fake Discom")
            yaraResult.matches.forEach { match ->
                when {
                    "OTP" in match.ruleName || "SMS" in match.ruleName -> add("OTP Interceptor")
                    "Overlay" in match.ruleName || "Cerberus" in match.ruleName -> add("Overlay Attack")
                    "Dropper" in match.ruleName || "DexClassLoader" in match.ruleName -> add("Dropper/Loader")
                    "Spyware" in match.description || "RAT" in match.description -> add("Spyware/RAT")
                    "Audio" in match.ruleName -> add("Audio Spyware")
                }
            }
            permResult.dangerousComboFlags.forEach { flag ->
                when {
                    "OTP" in flag -> add("OTP Interceptor")
                    "Stalker" in flag || "Location" in flag -> add("Stalkerware")
                    "Contact" in flag -> add("Contact Harvester")
                    "Dropper" in flag -> add("Dropper/Loader")
                }
            }
            if (c2Signal.verdictFromBeaconing != C2Verdict.NONE) add("C2 Communication")
            if (onnxResult.predictedClass != "Benign") add(onnxResult.predictedClass)
        }.distinct()

        return RiskScore(
            packageName = packageName,
            totalScore = total,
            riskLevel = riskLevel,
            breakdown = RiskBreakdown(
                yaraLite = yaraScore,
                indiaIoc = iocScore,
                c2Signals = c2Score,
                permissions = permScore,
                certificate = certScore,
                onnxAnomaly = anomalyScore,
                sideloaded = sideloadScore,
            ),
            threatCategories = categories,
            c2Verdict = c2Signal.verdictFromBeaconing,
        )
    }

    private fun computeC2Score(c2: C2Signal): Int {
        return when (c2.verdictFromBeaconing) {
            C2Verdict.CONFIRMED -> 40
            C2Verdict.LIKELY -> 25
            C2Verdict.SUSPECTED -> 15
            C2Verdict.NONE -> 0
        }
    }
}
