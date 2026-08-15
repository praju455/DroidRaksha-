package com.droidraksha.mobile.domain.engine

import android.content.Context
import com.droidraksha.mobile.domain.engine.model.YaraLiteResult
import com.droidraksha.mobile.domain.engine.model.YaraMatch
import dagger.hilt.android.qualifiers.ApplicationContext
import java.io.File
import java.util.zip.ZipFile
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Layer 2c Engine — YARA-Lite Pattern Matcher.
 *
 * A lightweight, JVM-native string-pattern engine that mimics YARA's most
 * impactful rules from [rules/malware.yar] and [rules/india_patterns.yar]
 * without requiring a native YARA binary or JNI bridge.
 *
 * How it works:
 *  1. Opens the APK (which is a ZIP file) and reads the DEX bytecode bytes
 *     as UTF-8 text (raw binary strings contain the Smali-level identifiers).
 *  2. Scans for high-signal string literals from the bundled rule set.
 *  3. Returns matches with severity labels and human-readable descriptions.
 *
 * Only reads the first [MAX_DEX_BYTES] of each DEX to bound memory usage.
 */
@Singleton
class YaraLiteMatcher @Inject constructor(
    @ApplicationContext private val context: Context,
) {
    companion object {
        private const val MAX_DEX_BYTES = 2 * 1024 * 1024  // 2 MB per DEX file
    }

    /**
     * Scan the APK at [apkPath] against all YARA-Lite rules.
     * [apkPath] can be obtained from [PackageManager.getApplicationInfo().sourceDir].
     */
    fun scan(packageName: String, apkPath: String): YaraLiteResult {
        val content = extractDexContent(apkPath)
        val matches = mutableListOf<YaraMatch>()

        for (rule in YARA_LITE_RULES) {
            for (pattern in rule.patterns) {
                if (pattern.containsMatchIn(content)) {
                    matches.add(
                        YaraMatch(
                            ruleName = rule.name,
                            severity = rule.severity,
                            description = rule.description,
                            matchedString = pattern.find(content)?.value?.take(80) ?: "",
                        )
                    )
                    break  // one hit per rule is sufficient
                }
            }
        }

        // Score: mirrors backend YARA scoring (CRITICAL=25, HIGH=15, MEDIUM=8, LOW=3), cap 30
        val SEVERITY_SCORES = mapOf("CRITICAL" to 25, "HIGH" to 15, "MEDIUM" to 8, "LOW" to 3)
        val score = matches.sumOf { SEVERITY_SCORES[it.severity] ?: 8 }.coerceAtMost(30)

        return YaraLiteResult(
            packageName = packageName,
            matches = matches,
            yaraRiskScore = score,
        )
    }

    private fun extractDexContent(apkPath: String): String {
        return buildString {
            runCatching {
                ZipFile(File(apkPath)).use { zip ->
                    zip.entries().asSequence()
                        .filter { it.name.endsWith(".dex") || it.name == "AndroidManifest.xml" }
                        .take(3)  // scan up to 3 DEX files
                        .forEach { entry ->
                            val bytes = zip.getInputStream(entry)
                                .readNBytes(MAX_DEX_BYTES)
                            // Interpret raw bytes as Latin-1 to preserve all byte values
                            append(String(bytes, Charsets.ISO_8859_1))
                            append("\n")
                        }
                }
            }
        }
    }

    // ── YARA-Lite Rule Set ────────────────────────────────────────────────
    // Selected high-signal rules ported from rules/malware.yar and rules/india_patterns.yar

    private data class YaraLiteRule(
        val name: String,
        val severity: String,
        val description: String,
        val patterns: List<Regex>,
    )

    private val YARA_LITE_RULES: List<YaraLiteRule> = listOf(

        // ── C2 Framework Signatures (CRITICAL) ─────────────────────────
        YaraLiteRule(
            name = "AndroRAT_Signature",
            severity = "CRITICAL",
            description = "AndroRAT Remote Access Trojan signature detected in DEX bytecode.",
            patterns = listOf(
                Regex("androrat", RegexOption.IGNORE_CASE),
                Regex("com\\.androrat", RegexOption.IGNORE_CASE),
                Regex("myServer\\.start", RegexOption.IGNORE_CASE),
            )
        ),
        YaraLiteRule(
            name = "AhMyth_Signature",
            severity = "CRITICAL",
            description = "AhMyth RAT — camera/microphone/file exfiltration trojan.",
            patterns = listOf(
                Regex("ahmyth", RegexOption.IGNORE_CASE),
                Regex("io\\.github\\.sangrobot"),
            )
        ),
        YaraLiteRule(
            name = "SpyNote_Signature",
            severity = "CRITICAL",
            description = "SpyNote/CraxsRAT — keylogger and screen capture RAT.",
            patterns = listOf(
                Regex("spynote", RegexOption.IGNORE_CASE),
                Regex("com\\.craxsrat", RegexOption.IGNORE_CASE),
                Regex("CRAXSRAT"),
            )
        ),
        YaraLiteRule(
            name = "Cerberus_Anubis_Trojan",
            severity = "CRITICAL",
            description = "Cerberus/Anubis banking trojan — targets UPI and Indian banking apps with overlay attacks.",
            patterns = listOf(
                Regex("cerberus", RegexOption.IGNORE_CASE),
                Regex("injectView.*overlay", RegexOption.IGNORE_CASE),
                Regex("overlay.*paytm", RegexOption.IGNORE_CASE),
                Regex("overlay.*phonepe", RegexOption.IGNORE_CASE),
                Regex("overlay.*gpay", RegexOption.IGNORE_CASE),
            )
        ),
        YaraLiteRule(
            name = "Metasploit_Meterpreter",
            severity = "CRITICAL",
            description = "Metasploit Meterpreter stager payload detected.",
            patterns = listOf(
                Regex("meterpreter", RegexOption.IGNORE_CASE),
                Regex("com/metasploit"),
                Regex("reverse_tcp"),
                Regex("reverse_https"),
            )
        ),
        YaraLiteRule(
            name = "CobaltStrike_Beacon",
            severity = "CRITICAL",
            description = "Cobalt Strike beacon implant — used by APT groups for persistent access.",
            patterns = listOf(
                Regex("cobaltstrike", RegexOption.IGNORE_CASE),
                Regex("MalleableC2"),
                Regex("sleep.*jitter"),
                Regex("checksum8"),
            )
        ),

        // ── OTP / Banking Intercept (CRITICAL) ─────────────────────────
        YaraLiteRule(
            name = "OTP_Interceptor",
            severity = "CRITICAL",
            description = "OTP interception pattern: reads SMS and forwards to remote server.",
            patterns = listOf(
                Regex("SmsMessage.*getOriginatingAddress.*send", RegexOption.IGNORE_CASE),
                Regex("onSmsReceived.*HttpPost", RegexOption.IGNORE_CASE),
                Regex("SMS_RECEIVED.*uploadOTP", RegexOption.IGNORE_CASE),
            )
        ),

        // ── DNS Tunneling (HIGH) ────────────────────────────────────────
        YaraLiteRule(
            name = "DNS_Tunneling",
            severity = "HIGH",
            description = "DNS tunneling pattern — data exfiltration over DNS TXT queries.",
            patterns = listOf(
                Regex("TYPE_TXT"),
                Regex("iodine", RegexOption.IGNORE_CASE),
                Regex("dnscat", RegexOption.IGNORE_CASE),
                Regex("dns.*exfil", RegexOption.IGNORE_CASE),
            )
        ),

        // ── Tor Routing (HIGH) ──────────────────────────────────────────
        YaraLiteRule(
            name = "Tor_Routing",
            severity = "HIGH",
            description = "Tor / anonymous routing detected — app routes traffic through onion network.",
            patterns = listOf(
                Regex("\\.onion"),
                Regex("SOCKS5.*127\\.0\\.0\\.1.*9050"),
                Regex("torproject", RegexOption.IGNORE_CASE),
            )
        ),

        // ── Generic HTTP Beacon (HIGH) ──────────────────────────────────
        YaraLiteRule(
            name = "Generic_HTTP_Beacon",
            severity = "HIGH",
            description = "Periodic HTTP call pattern near Thread.sleep() — generic C2 beaconing.",
            patterns = listOf(
                Regex("Thread\\.sleep.*HttpURLConnection", RegexOption.DOT_MATCHES_ALL),
                Regex("Timer.*HttpPost"),
                Regex("ScheduledExecutorService.*HttpClient"),
            )
        ),

        // ── India-specific patterns (HIGH) ──────────────────────────────
        YaraLiteRule(
            name = "India_UPI_Phishing",
            severity = "HIGH",
            description = "Hardcoded Indian UPI phishing domain or fake NPCI/RBI string detected.",
            patterns = listOf(
                Regex("upi-support-helpline", RegexOption.IGNORE_CASE),
                Regex("npci-help\\.in", RegexOption.IGNORE_CASE),
                Regex("sbi-secure-login", RegexOption.IGNORE_CASE),
                Regex("paytm-kyc-update", RegexOption.IGNORE_CASE),
                Regex("aadhaar-update-online", RegexOption.IGNORE_CASE),
            )
        ),
        YaraLiteRule(
            name = "India_Loan_Scam",
            severity = "HIGH",
            description = "Hardcoded loan-scam domain or string pattern detected targeting Indian users.",
            patterns = listOf(
                Regex("fastcashloan\\.in", RegexOption.IGNORE_CASE),
                Regex("easyrupee\\.xyz", RegexOption.IGNORE_CASE),
                Regex("instantloan24\\.in", RegexOption.IGNORE_CASE),
                Regex("loan.*instant.*approv", RegexOption.IGNORE_CASE),
            )
        ),

        // ── Anti-Analysis Evasion (MEDIUM) ─────────────────────────────
        YaraLiteRule(
            name = "Emulator_Detection",
            severity = "MEDIUM",
            description = "App checks for emulator environment — common evasion technique in malware.",
            patterns = listOf(
                Regex("android\\.os\\.Build.*FINGERPRINT.*generic", RegexOption.IGNORE_CASE),
                Regex("getSystemProperty.*ro\\.product\\.model.*sdk", RegexOption.IGNORE_CASE),
                Regex("isEmulator", RegexOption.IGNORE_CASE),
            )
        ),
        YaraLiteRule(
            name = "DexClassLoader_Dropper",
            severity = "HIGH",
            description = "Dynamic code loading via DexClassLoader — classic dropper/loader pattern used to load secondary payloads.",
            patterns = listOf(
                Regex("dalvik\\.system\\.DexClassLoader"),
                Regex("BaseDexClassLoader.*dexPath"),
                Regex("PathClassLoader.*load"),
            )
        ),
        YaraLiteRule(
            name = "Native_Code_Exec",
            severity = "MEDIUM",
            description = "Native code execution via Runtime.exec() or ProcessBuilder — can spawn shell commands.",
            patterns = listOf(
                Regex("Runtime\\.getRuntime.*exec"),
                Regex("ProcessBuilder.*start"),
                Regex("/system/bin/sh"),
            )
        ),
    )
}
