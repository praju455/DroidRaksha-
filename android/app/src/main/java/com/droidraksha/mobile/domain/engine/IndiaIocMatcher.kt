package com.droidraksha.mobile.domain.engine

import android.content.Context
import com.droidraksha.mobile.domain.engine.model.IocMatchResult
import com.squareup.moshi.Moshi
import com.squareup.moshi.Types
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Layer 2b Engine — India IOC (Indicator of Compromise) Matcher.
 *
 * Loads [india_iocs.json] from the app's assets directory at first use
 * and matches each app's package name against:
 *   - Known fake UPI / banking / loan-scam package blacklists
 *   - Fraudulent domains embedded in the APK's metadata
 *   - Known malicious IPs used in Indian banking trojan campaigns
 *   - Regex patterns for UPI helpline fraud strings
 *   - Fake Discom (electricity utility) phishing patterns
 *
 * Ported faithfully from [backend/intel/india_ioc.py].
 */
@Singleton
class IndiaIocMatcher @Inject constructor(
    @ApplicationContext private val context: Context,
    private val moshi: Moshi,
) {
    // Lazily loaded intel — parsed once from assets on first call
    private val intel: IndiaIocDatabase by lazy { loadIntel() }

    /**
     * Match [packageName] against all India-specific IOC databases.
     * [declaredDomains] and [declaredIps] should be extracted from the APK's
     * network-related string literals where available; can be empty.
     */
    fun match(
        packageName: String,
        declaredDomains: List<String> = emptyList(),
        declaredIps: List<String> = emptyList(),
    ): IocMatchResult {
        val riskFlags = mutableListOf<String>()
        val matchedPackages = mutableListOf<String>()
        val matchedDomains = mutableListOf<String>()
        val matchedIps = mutableListOf<String>()

        var isFakeUpi = false
        var isFakeBank = false
        var isLoanScam = false
        var isFakeDiscom = false

        // ── 1. Exact package name blacklist ──────────────────────────────
        if (packageName in intel.fakePackages) {
            matchedPackages.add(packageName)
            isFakeUpi = true
            riskFlags.add("Package '$packageName' is in known fake-UPI/banking blacklist")
        }

        // ── 2. Loan scam package name keyword heuristic ──────────────────
        val loanKeywords = intel.loanScamKeywords
        if (loanKeywords.any { it in packageName.lowercase() }) {
            isLoanScam = true
            riskFlags.add("Package name '$packageName' matches loan-scam naming pattern")
        }

        // ── 3. Fraudulent domain matching ────────────────────────────────
        for (domain in declaredDomains) {
            for (fraudDomain in intel.fraudulentDomains) {
                if (fraudDomain in domain) {
                    matchedDomains.add(fraudDomain)
                    isFakeBank = true
                    riskFlags.add("Communicates with known fraud domain: $fraudDomain")
                }
            }
            // India-specific C2 domain patterns
            for (pattern in intel.indiaC2DomainPatterns) {
                if (Regex(pattern, RegexOption.IGNORE_CASE).containsMatchIn(domain)) {
                    matchedDomains.add(domain)
                    isFakeBank = true
                    riskFlags.add("Matches India C2 domain pattern: $pattern")
                }
            }
        }

        // ── 4. Malicious IP matching ──────────────────────────────────────
        for (ip in declaredIps) {
            if (ip in intel.maliciousIps) {
                matchedIps.add(ip)
                riskFlags.add("Connects to known malicious IP used in Indian banking attacks: $ip")
            }
        }

        // ── 5. UPI fraud string patterns (regex) ─────────────────────────
        val combinedText = (declaredDomains + declaredIps).joinToString(" ").lowercase()
        for (pattern in intel.upiFraudPatterns) {
            if (Regex(pattern, RegexOption.IGNORE_CASE).containsMatchIn(combinedText)) {
                isFakeUpi = true
                riskFlags.add("String pattern matches UPI/banking fraud: '$pattern'")
                break
            }
        }

        // ── 6. Fake Discom (electricity board) patterns ───────────────────
        for (pattern in intel.discomFakePatterns) {
            if (Regex(pattern, RegexOption.IGNORE_CASE).containsMatchIn(packageName + " " + combinedText)) {
                isFakeDiscom = true
                riskFlags.add("Matches fake electricity/discom phishing pattern: '$pattern'")
                break
            }
        }

        // ── IOC risk score (primary signal, max 30 pts) ───────────────────
        var iocScore = 0
        if (isFakeUpi) iocScore += 20
        if (isFakeBank) iocScore += 20
        if (isLoanScam) iocScore += 15
        if (isFakeDiscom) iocScore += 20
        iocScore += matchedIps.size * 5
        iocScore += matchedDomains.size * 5

        return IocMatchResult(
            packageName = packageName,
            isFakeUpi = isFakeUpi,
            isFakeBank = isFakeBank,
            isLoanScam = isLoanScam,
            isFakeDiscom = isFakeDiscom,
            matchedPackages = matchedPackages.distinct(),
            matchedDomains = matchedDomains.distinct(),
            matchedIps = matchedIps.distinct(),
            riskFlags = riskFlags.distinct(),
            iocRiskScore = minOf(30, iocScore),
        )
    }

    // ── Asset loader ──────────────────────────────────────────────────────

    private fun loadIntel(): IndiaIocDatabase {
        val json = context.assets.open("india_iocs.json").bufferedReader().readText()
        val adapter = moshi.adapter(IndiaIocDatabase::class.java)
        return adapter.fromJson(json) ?: IndiaIocDatabase()
    }

    // ── Moshi-compatible data class mirroring india_iocs.json ────────────

    data class IndiaIocDatabase(
        val fake_packages: List<String> = emptyList(),
        val fraudulent_domains: List<String> = emptyList(),
        val malicious_ips: List<String> = emptyList(),
        val loan_scam_keywords: List<String> = emptyList(),
        val upi_fraud_patterns: List<String> = emptyList(),
        val india_c2_domain_patterns: List<String> = emptyList(),
        val discom_fake_patterns: List<String> = emptyList(),
    ) {
        val fakePackages get() = fake_packages.toSet()
        val fraudulentDomains get() = fraudulent_domains.toSet()
        val maliciousIps get() = malicious_ips.toSet()
        val loanScamKeywords get() = loan_scam_keywords
        val upiFraudPatterns get() = upi_fraud_patterns
        val indiaC2DomainPatterns get() = india_c2_domain_patterns
        val discomFakePatterns get() = discom_fake_patterns
    }
}
