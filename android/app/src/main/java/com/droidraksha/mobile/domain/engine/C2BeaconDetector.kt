package com.droidraksha.mobile.domain.engine

import android.content.Context
import com.droidraksha.mobile.domain.engine.model.YaraLiteResult
import com.droidraksha.mobile.domain.model.C2Signal
import com.droidraksha.mobile.domain.model.C2Verdict
import com.droidraksha.mobile.domain.model.NetworkMetrics
import com.squareup.moshi.Moshi
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Layer 3b Engine — C2 Beacon Detector.
 *
 * Combines three data sources to produce a consolidated [C2Signal]:
 *
 *  1. **Network CoV beaconing** from [NetworkTrafficMonitor] — detects
 *     automated, regular-interval connections characteristic of C2 bots.
 *
 *  2. **YARA-Lite framework signatures** from [YaraLiteMatcher] — identifies
 *     known RAT/C2 framework strings (AndroRAT, Cerberus, Cobalt Strike, etc.)
 *     in the DEX bytecode.
 *
 *  3. **Bundled C2 threat intelligence** from [c2_threat_intel.json] — matches
 *     hardcoded IPs/domains against known C2 infrastructure.
 *
 * Produces a final [C2Verdict]:
 *  - NONE (< 15 pts)
 *  - SUSPECTED (15–39 pts)
 *  - LIKELY (40–69 pts)
 *  - CONFIRMED (≥ 70 pts)
 *
 * Ported from [backend/intel/c2_detector.py].
 */
@Singleton
class C2BeaconDetector @Inject constructor(
    @ApplicationContext private val context: Context,
    private val moshi: Moshi,
) {
    private val c2Intel: C2ThreatDatabase by lazy { loadC2Intel() }

    /**
     * Combine network metrics and YARA-Lite results into a single C2 verdict.
     */
    fun detect(
        packageName: String,
        networkMetrics: NetworkMetrics?,
        yaraResult: YaraLiteResult,
        declaredDomains: List<String> = emptyList(),
        declaredIps: List<String> = emptyList(),
    ): C2Signal {
        var c2Score = 0
        val reasons = mutableListOf<String>()

        // ── 1. Network CoV beaconing ────────────────────────────────────
        if (networkMetrics != null) {
            if (networkMetrics.isBeaconingFlagged) {
                c2Score += 25
                reasons.add(
                    "Beaconing detected: CoV=${String.format("%.2f", networkMetrics.intervalCoefficientOfVariation)}" +
                    " over ${networkMetrics.connectionIntervals.size} intervals. Regular connections indicate automated C2 check-ins."
                )
            }
            // High background traffic ratio (> 80% traffic in background) is suspicious
            val totalTraffic = networkMetrics.rxBytesLast24h + networkMetrics.txBytesLast24h
            if (totalTraffic > 0) {
                val bgRatio = (networkMetrics.backgroundRxBytes + networkMetrics.backgroundTxBytes).toFloat() / totalTraffic
                if (bgRatio > 0.8f) {
                    c2Score += 10
                    reasons.add("High background traffic ratio: ${(bgRatio * 100).toInt()}% traffic is background. Possible silent exfiltration.")
                }
            }
        }

        // ── 2. YARA framework hits (CRITICAL = +40, HIGH = +20) ─────────
        for (match in yaraResult.matches) {
            when (match.severity) {
                "CRITICAL" -> {
                    c2Score += 40
                    reasons.add("CRITICAL C2 framework: ${match.ruleName} — ${match.description}")
                }
                "HIGH" -> {
                    c2Score += 20
                    reasons.add("HIGH severity pattern: ${match.ruleName} — ${match.description}")
                }
            }
        }

        // ── 3. Bundled C2 threat intel — domain matching ─────────────────
        val matchedIndiaDomains = mutableListOf<String>()
        for (domain in declaredDomains) {
            for (pattern in c2Intel.indiaC2DomainPatterns) {
                if (Regex(pattern, RegexOption.IGNORE_CASE).containsMatchIn(domain)) {
                    matchedIndiaDomains.add(domain)
                    c2Score += 10
                    reasons.add("Matches India-specific C2 domain pattern: $domain")
                    break
                }
            }
            // Tor .onion routing
            if (domain.endsWith(".onion")) {
                c2Score += 30
                reasons.add("Connects to Tor hidden service: $domain")
            }
        }

        // ── 4. High-risk IP matching ──────────────────────────────────────
        for (ip in declaredIps) {
            if (ip in c2Intel.knownMaliciousIps) {
                c2Score += 15
                reasons.add("Connects to known C2 IP: $ip")
            }
        }

        c2Score = c2Score.coerceAtMost(100)

        val verdict = when {
            c2Score >= 70 -> C2Verdict.CONFIRMED
            c2Score >= 40 -> C2Verdict.LIKELY
            c2Score >= 15 -> C2Verdict.SUSPECTED
            else -> C2Verdict.NONE
        }

        return C2Signal(
            packageName = packageName,
            verdictFromBeaconing = verdict,
            beaconingCoV = networkMetrics?.intervalCoefficientOfVariation ?: 1f,
            sampleIntervalCount = networkMetrics?.connectionIntervals?.size ?: 0,
            reason = if (reasons.isEmpty()) "No C2 indicators detected."
                     else "[${verdict.name}] " + reasons.joinToString(". "),
        )
    }

    // ── Asset loader ──────────────────────────────────────────────────────

    private fun loadC2Intel(): C2ThreatDatabase {
        val json = context.assets.open("c2_threat_intel.json").bufferedReader().readText()
        return runCatching {
            moshi.adapter(C2ThreatDatabase::class.java).fromJson(json)!!
        }.getOrDefault(C2ThreatDatabase())
    }

    data class C2ThreatDatabase(
        val india_c2_domain_patterns: List<String> = emptyList(),
        val tor_patterns: List<String> = emptyList(),
        val known_malicious_ips: List<String> = emptyList(),
    ) {
        val indiaC2DomainPatterns get() = india_c2_domain_patterns
        val knownMaliciousIps get() = known_malicious_ips.toSet()
    }
}
