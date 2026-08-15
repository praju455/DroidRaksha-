package com.droidraksha.mobile.domain.engine

import android.content.Context
import android.content.pm.PackageManager
import com.droidraksha.mobile.data.local.entity.AppEntity
import com.droidraksha.mobile.data.local.entity.ScanHistoryEntity
import com.droidraksha.mobile.data.repository.AppRepository
import com.droidraksha.mobile.domain.model.C2Verdict
import com.droidraksha.mobile.domain.model.RiskLevel
import com.squareup.moshi.Moshi
import com.squareup.moshi.Types
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Scan Orchestrator — coordinates all 4 detection layers for a full-device scan.
 *
 * Execution order per app:
 *   Layer 1: AppInventoryScanner  → raw metadata
 *   Layer 2: PermissionComboAnalyzer + IndiaIocMatcher + YaraLiteMatcher + OnDeviceMLInference
 *   Layer 3: NetworkTrafficMonitor + C2BeaconDetector
 *   Layer 4: LocalRiskScorer → final 0–100 score + verdict
 *
 * All engine calls run on [Dispatchers.Default] (CPU-bound). Database writes
 * are batched and executed on [Dispatchers.IO].
 *
 * Callers observe scan state via the [ScanState] sealed class.
 */
@Singleton
class ScanOrchestrator @Inject constructor(
    @ApplicationContext private val context: Context,
    private val inventoryScanner: AppInventoryScanner,
    private val permissionAnalyzer: PermissionComboAnalyzer,
    private val iocMatcher: IndiaIocMatcher,
    private val yaraLiteMatcher: YaraLiteMatcher,
    private val mlInference: OnDeviceMLInference,
    private val networkMonitor: NetworkTrafficMonitor,
    private val c2Detector: C2BeaconDetector,
    private val riskScorer: LocalRiskScorer,
    private val repository: AppRepository,
    private val moshi: Moshi,
) {
    sealed class ScanState {
        object Idle : ScanState()
        data class Scanning(val current: Int, val total: Int, val currentAppName: String) : ScanState()
        data class Completed(val criticalCount: Int, val highCount: Int, val sessionId: Long) : ScanState()
        data class Error(val message: String) : ScanState()
    }

    private val pm: PackageManager = context.packageManager
    private val stringListAdapter = moshi.adapter<List<String>>(
        Types.newParameterizedType(List::class.java, String::class.java)
    )

    /**
     * Run a complete scan of all installed apps.
     *
     * @param onProgress Callback invoked as each app is scanned.
     * @param triggeredBy "manual" | "schedule" | "package_install"
     * @return [ScanState.Completed] on success or [ScanState.Error] on failure.
     */
    suspend fun runFullScan(
        onProgress: (ScanState.Scanning) -> Unit = {},
        triggeredBy: String = "manual",
    ): ScanState = withContext(Dispatchers.Default) {
        val scanStart = System.currentTimeMillis()

        // ── Layer 1: enumerate installed apps ────────────────────────────
        val rawEntities = inventoryScanner.scanInstalledApps()
        val total = rawEntities.size
        val scannedEntities = mutableListOf<AppEntity>()

        rawEntities.forEachIndexed { index, baseEntity ->
            val appName = baseEntity.appName
            onProgress(ScanState.Scanning(index + 1, total, appName))

            val scored = scoreSingleApp(baseEntity)
            scannedEntities.add(scored)
        }

        // ── Persist results ──────────────────────────────────────────────
        withContext(Dispatchers.IO) {
            repository.upsertAll(scannedEntities)
            repository.pruneUninstalledApps(scannedEntities.map { it.packageName })
        }

        // ── Record scan session ──────────────────────────────────────────
        val criticalCount = scannedEntities.count { it.riskLevel == "CRITICAL" }
        val highCount = scannedEntities.count { it.riskLevel == "HIGH" }
        val mediumCount = scannedEntities.count { it.riskLevel == "MEDIUM" }
        val lowCount = scannedEntities.count { it.riskLevel == "LOW" }
        val safeCount = scannedEntities.count { it.riskLevel == "SAFE" }

        val deviceScore = computeDeviceScore(scannedEntities)

        val sessionId = withContext(Dispatchers.IO) {
            repository.recordScanSession(
                ScanHistoryEntity(
                    scanStartedAt = scanStart,
                    scanCompletedAt = System.currentTimeMillis(),
                    totalAppsScanned = total,
                    criticalCount = criticalCount,
                    highCount = highCount,
                    mediumCount = mediumCount,
                    lowCount = lowCount,
                    safeCount = safeCount,
                    newlyFlaggedPackages = "[]",
                    deviceOverallScore = deviceScore,
                    triggeredBy = triggeredBy,
                )
            )
        }

        ScanState.Completed(criticalCount = criticalCount, highCount = highCount, sessionId = sessionId)
    }

    /**
     * Scan a single app (used when [ACTION_PACKAGE_ADDED] is received
     * for a newly installed app).
     */
    suspend fun scanSingleApp(packageName: String): ScanState = withContext(Dispatchers.Default) {
        val entities = inventoryScanner.scanInstalledApps()
        val base = entities.find { it.packageName == packageName }
            ?: return@withContext ScanState.Error("Package not found: $packageName")

        val scored = scoreSingleApp(base)
        withContext(Dispatchers.IO) { repository.upsert(scored) }

        ScanState.Completed(
            criticalCount = if (scored.riskLevel == "CRITICAL") 1 else 0,
            highCount = if (scored.riskLevel == "HIGH") 1 else 0,
            sessionId = -1L,
        )
    }

    // ── Per-app scoring pipeline ──────────────────────────────────────────

    private suspend fun scoreSingleApp(base: AppEntity): AppEntity = coroutineScope {
        val pkg = base.packageName
        val apkPath = runCatching {
            pm.getApplicationInfo(pkg, 0).sourceDir
        }.getOrNull()
        val uid = runCatching {
            pm.getApplicationInfo(pkg, 0).uid
        }.getOrDefault(-1)

        // Layer 2 — run all detection engines in parallel
        val permDeferred = async { permissionAnalyzer.analyze(pkg) }
        val yaraDeferred = async { if (apkPath != null) yaraLiteMatcher.scan(pkg, apkPath) else null }
        val onnxDeferred = async { runCatching { mlInference.classify(pkg, apkPath) }.getOrNull() }
        val netDeferred = async {
            if (uid > 0) runCatching { networkMonitor.getMetrics(pkg, uid) }.getOrNull() else null
        }
        val iocDeferred = async { iocMatcher.match(pkg) }

        val permResult = permDeferred.await()
        val yaraResult = yaraDeferred.await()
        val onnxResult = onnxDeferred.await()
        val networkMetrics = netDeferred.await()
        val iocResult = iocDeferred.await()

        // Provide defaults if engines returned null
        val safeYara = yaraResult ?: com.droidraksha.mobile.domain.engine.model.YaraLiteResult(pkg, emptyList(), 0)
        val safeOnnx = onnxResult ?: com.droidraksha.mobile.domain.engine.model.OnnxInferenceResult(
            packageName = pkg, predictedClass = "Benign", confidence = 1f,
            isAnomalyFlagged = false, classProbabilities = mapOf("Benign" to 1f)
        )

        // Layer 3 — C2 beacon detection
        val c2Signal = c2Detector.detect(pkg, networkMetrics, safeYara)

        // Layer 4 — risk scoring
        val riskScore = riskScorer.score(
            packageName = pkg,
            yaraResult = safeYara,
            iocResult = iocResult,
            c2Signal = c2Signal,
            permResult = permResult,
            onnxResult = safeOnnx,
            isSelfSigned = base.isSelfSigned,
            isDebugCert = base.isDebugCert,
            installSource = base.installSource,
        )

        // Merge scored results back into the entity
        base.copy(
            riskScore = riskScore.totalScore,
            riskLevel = riskScore.riskLevel.name,
            threatCategories = stringListAdapter.toJson(riskScore.threatCategories),
            isFakeUpi = iocResult.isFakeUpi,
            isFakeBank = iocResult.isFakeBank,
            isLoanScam = iocResult.isLoanScam,
            matchedIocDomains = stringListAdapter.toJson(iocResult.matchedDomains),
            dangerousPermissions = stringListAdapter.toJson(permResult.dangerousPermissions),
            dangerousComboFlags = stringListAdapter.toJson(permResult.dangerousComboFlags),
            c2Verdict = c2Signal.verdictFromBeaconing.name,
            c2ConfidenceScore = riskScore.breakdown.c2Signals,
            detectedC2Frameworks = stringListAdapter.toJson(
                safeYara.matches.filter { it.severity == "CRITICAL" }.map { it.ruleName }
            ),
            onnxPredictedClass = safeOnnx.predictedClass,
            onnxConfidence = safeOnnx.confidence,
            isAnomalyFlagged = safeOnnx.isAnomalyFlagged,
            lastScannedAt = System.currentTimeMillis(),
        )
    }

    /**
     * Compute an overall device security score (0–100 where higher = more risky).
     * Weighted average with CRITICAL apps pulling heavily.
     */
    private fun computeDeviceScore(apps: List<AppEntity>): Int {
        if (apps.isEmpty()) return 0
        val weighted = apps.sumOf { app ->
            when (app.riskLevel) {
                "CRITICAL" -> app.riskScore * 3
                "HIGH" -> app.riskScore * 2
                else -> app.riskScore
            }
        }
        val maxPossible = apps.size * 100 * 3  // assume worst case all CRITICAL
        return ((weighted.toFloat() / maxPossible) * 100).toInt().coerceIn(0, 100)
    }
}
