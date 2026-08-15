package com.droidraksha.mobile.domain.engine

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import com.droidraksha.mobile.domain.engine.model.PermissionAnalysisResult
import com.squareup.moshi.Moshi
import com.squareup.moshi.Types
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Layer 2a Engine — Permission Combination Analyzer.
 *
 * Detects dangerous Android permission combinations that are characteristic
 * of specific malware families. Logic is ported directly from the backend's
 * [manifest_parser.py] and expanded with additional Indian mobile threat patterns.
 *
 * All dangerous combos are weighted and explained in plain English.
 */
@Singleton
class PermissionComboAnalyzer @Inject constructor(
    @ApplicationContext private val context: Context,
    private val moshi: Moshi,
) {
    private val pm: PackageManager = context.packageManager
    private val stringListAdapter = moshi.adapter<List<String>>(
        Types.newParameterizedType(List::class.java, String::class.java)
    )

    /**
     * Analyze the permission set for [packageName].
     *
     * @return [PermissionAnalysisResult] containing the list of dangerous permissions
     *         found, matched combo descriptions, and a partial permission risk score.
     */
    fun analyze(packageName: String): PermissionAnalysisResult {
        val declaredPerms = runCatching {
            val flags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU)
                PackageManager.GET_PERMISSIONS else PackageManager.GET_PERMISSIONS
            pm.getPackageInfo(packageName, flags).requestedPermissions?.toSet() ?: emptySet()
        }.getOrDefault(emptySet())

        // Identify declared dangerous permissions
        val dangerous = DANGEROUS_PERMISSIONS.filter { it in declaredPerms }

        // Check each combo rule
        val matchedCombos = DANGEROUS_COMBOS.filter { combo ->
            combo.required.all { it in declaredPerms }
        }

        val permScore = minOf(10, dangerous.size * 1 + matchedCombos.size * 5)

        return PermissionAnalysisResult(
            packageName = packageName,
            dangerousPermissions = dangerous,
            dangerousComboFlags = matchedCombos.map { it.description },
            permissionRiskScore = permScore,
            totalPermissionCount = declaredPerms.size,
        )
    }

    // ── Known individual dangerous permissions ────────────────────────────
    private val DANGEROUS_PERMISSIONS = setOf(
        "android.permission.READ_SMS",
        "android.permission.SEND_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.READ_CALL_LOG",
        "android.permission.PROCESS_OUTGOING_CALLS",
        "android.permission.RECORD_AUDIO",
        "android.permission.CAMERA",
        "android.permission.READ_CONTACTS",
        "android.permission.WRITE_CONTACTS",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.READ_PHONE_STATE",
        "android.permission.BIND_ACCESSIBILITY_SERVICE",
        "android.permission.SYSTEM_ALERT_WINDOW",
        "android.permission.WRITE_SETTINGS",
        "android.permission.RECEIVE_BOOT_COMPLETED",
        "android.permission.REQUEST_INSTALL_PACKAGES",
        "android.permission.QUERY_ALL_PACKAGES",
        "android.permission.USE_BIOMETRIC",
        "android.permission.USE_FINGERPRINT",
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.MOUNT_UNMOUNT_FILESYSTEMS",
        "android.permission.KILL_BACKGROUND_PROCESSES",
        "android.permission.CHANGE_NETWORK_STATE",
        "android.permission.DEVICE_POWER",
    )

    // ── High-signal dangerous permission combinations ─────────────────────
    // Each combo maps to a threat category and description explaining the attack vector.
    private data class ComboRule(
        val required: Set<String>,
        val description: String,
        val threat: String,
    )

    private val DANGEROUS_COMBOS: List<ComboRule> = listOf(
        ComboRule(
            required = setOf(
                "android.permission.READ_SMS",
                "android.permission.INTERNET"
            ),
            description = "READ_SMS + INTERNET: Can silently intercept OTP codes and exfiltrate them to a remote server. High risk for banking fraud.",
            threat = "OTP Interceptor"
        ),
        ComboRule(
            required = setOf(
                "android.permission.RECORD_AUDIO",
                "android.permission.INTERNET"
            ),
            description = "RECORD_AUDIO + INTERNET: Can record microphone audio and stream it to a C2 server in real-time. Classic spyware pattern.",
            threat = "Audio Spyware"
        ),
        ComboRule(
            required = setOf(
                "android.permission.BIND_ACCESSIBILITY_SERVICE",
                "android.permission.INTERNET"
            ),
            description = "BIND_ACCESSIBILITY_SERVICE + INTERNET: Can perform overlay attacks, simulate taps, read screen content, and exfiltrate data. Used by Cerberus / Anubis banking trojans.",
            threat = "Overlay / Keylogger"
        ),
        ComboRule(
            required = setOf(
                "android.permission.READ_CONTACTS",
                "android.permission.INTERNET"
            ),
            description = "READ_CONTACTS + INTERNET: Can harvest contact lists and upload them to a remote server. Used by loan scam apps for blackmail and social engineering.",
            threat = "Contact Harvester"
        ),
        ComboRule(
            required = setOf(
                "android.permission.QUERY_ALL_PACKAGES",
                "android.permission.SYSTEM_ALERT_WINDOW"
            ),
            description = "QUERY_ALL_PACKAGES + SYSTEM_ALERT_WINDOW: Can detect installed banking apps and display fake overlay screens over them to steal credentials.",
            threat = "Fake UI Overlay"
        ),
        ComboRule(
            required = setOf(
                "android.permission.CAMERA",
                "android.permission.INTERNET"
            ),
            description = "CAMERA + INTERNET: Can take photos or stream video and exfiltrate to remote server. Used by RATs like AhMyth and SpyNote.",
            threat = "Camera RAT"
        ),
        ComboRule(
            required = setOf(
                "android.permission.ACCESS_FINE_LOCATION",
                "android.permission.INTERNET"
            ),
            description = "ACCESS_FINE_LOCATION + INTERNET: Can track precise GPS coordinates and report to a tracking/stalkerware server.",
            threat = "Location Stalkerware"
        ),
        ComboRule(
            required = setOf(
                "android.permission.REQUEST_INSTALL_PACKAGES",
                "android.permission.INTERNET"
            ),
            description = "REQUEST_INSTALL_PACKAGES + INTERNET: Can silently download and install secondary malicious APKs. Classic dropper/loader behavior.",
            threat = "Dropper / Loader"
        ),
        ComboRule(
            required = setOf(
                "android.permission.RECEIVE_BOOT_COMPLETED",
                "android.permission.INTERNET",
                "android.permission.READ_SMS"
            ),
            description = "RECEIVE_BOOT_COMPLETED + INTERNET + READ_SMS: Starts on device boot, intercepts SMS, and communicates with C2. Persistent banking trojan pattern.",
            threat = "Persistent Banking Trojan"
        ),
        ComboRule(
            required = setOf(
                "android.permission.READ_PHONE_STATE",
                "android.permission.SEND_SMS",
                "android.permission.INTERNET"
            ),
            description = "READ_PHONE_STATE + SEND_SMS + INTERNET: Can harvest device IMEI, trigger premium SMS charges, and report back to C2. Classic SMS malware pattern.",
            threat = "SMS Malware / Fraud"
        ),
    )
}
