package com.droidraksha.mobile.data.repository

import com.droidraksha.mobile.data.local.dao.AppDao
import com.droidraksha.mobile.data.local.dao.ScanHistoryDao
import com.droidraksha.mobile.data.local.entity.AppEntity
import com.droidraksha.mobile.data.local.entity.ScanHistoryEntity
import com.droidraksha.mobile.domain.model.AppInfo
import com.droidraksha.mobile.domain.model.C2Verdict
import com.droidraksha.mobile.domain.model.InstallSource
import com.droidraksha.mobile.domain.model.RiskLevel
import com.squareup.moshi.Moshi
import com.squareup.moshi.Types
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Repository that bridges the Room data layer with domain models.
 *
 * Responsible for:
 * - Persisting scan results from the detection engines.
 * - Mapping [AppEntity] ↔ [AppInfo] domain models.
 * - Providing reactive [Flow] streams to ViewModels.
 */
@Singleton
class AppRepository @Inject constructor(
    private val appDao: AppDao,
    private val scanHistoryDao: ScanHistoryDao,
    private val moshi: Moshi,
) {
    private val stringListAdapter = moshi.adapter<List<String>>(
        Types.newParameterizedType(List::class.java, String::class.java)
    )

    // ── App queries (reactive Flows for Compose) ──────────────────────────

    fun getAllAppsOrderedByRisk(): Flow<List<AppInfo>> =
        appDao.getAllAppsOrderedByRisk().map { list -> list.map(::toAppInfo) }

    fun getAppsByRiskLevel(level: RiskLevel): Flow<List<AppInfo>> =
        appDao.getAppsByRiskLevel(level.name).map { list -> list.map(::toAppInfo) }

    fun getSideloadedApps(): Flow<List<AppInfo>> =
        appDao.getSideloadedApps().map { list -> list.map(::toAppInfo) }

    fun getMediumAndAbove(): Flow<List<AppInfo>> =
        appDao.getMediumAndAbove().map { list -> list.map(::toAppInfo) }

    fun getAppByPackage(packageName: String): Flow<AppInfo?> =
        appDao.getAppByPackage(packageName).map { it?.let(::toAppInfo) }

    // ── Dashboard count streams ───────────────────────────────────────────

    fun getCriticalCount(): Flow<Int> = appDao.getCriticalCount()
    fun getHighCount(): Flow<Int> = appDao.getHighCount()
    fun getMediumCount(): Flow<Int> = appDao.getMediumCount()
    fun getLowCount(): Flow<Int> = appDao.getLowCount()
    fun getSafeCount(): Flow<Int> = appDao.getSafeCount()
    fun getTotalCount(): Flow<Int> = appDao.getTotalCount()

    // ── Write operations ──────────────────────────────────────────────────

    suspend fun upsertAll(apps: List<AppEntity>) = appDao.upsertAll(apps)

    suspend fun upsert(app: AppEntity) = appDao.upsert(app)

    /**
     * After a scan, remove stale entries for apps that have been uninstalled.
     */
    suspend fun pruneUninstalledApps(currentPackages: List<String>) =
        appDao.deleteRemovedApps(currentPackages)

    // ── Scan history ──────────────────────────────────────────────────────

    fun getLatestSession() = scanHistoryDao.getLatestSession()

    fun getAllSessions() = scanHistoryDao.getAllSessions()

    suspend fun recordScanSession(session: ScanHistoryEntity): Long =
        scanHistoryDao.insert(session).also { scanHistoryDao.pruneOldSessions() }

    // ── Entity ↔ Domain mapping ───────────────────────────────────────────

    private fun toAppInfo(e: AppEntity): AppInfo = AppInfo(
        packageName = e.packageName,
        appName = e.appName,
        versionName = e.versionName,
        versionCode = e.versionCode,
        installedAt = e.installedAt,
        lastUpdated = e.lastUpdated,
        apkSizeBytes = e.apkSizeBytes,
        targetSdkVersion = e.targetSdkVersion,
        minSdkVersion = e.minSdkVersion,
        installSource = InstallSource.fromString(e.installSource),
        certIssuer = e.certIssuer,
        certSubject = e.certSubject,
        isSelfSigned = e.isSelfSigned,
        isDebugCert = e.isDebugCert,
        riskScore = e.riskScore,
        riskLevel = RiskLevel.fromString(e.riskLevel),
        threatCategories = stringListAdapter.fromJson(e.threatCategories) ?: emptyList(),
        isFakeUpi = e.isFakeUpi,
        isFakeBank = e.isFakeBank,
        isLoanScam = e.isLoanScam,
        matchedIocDomains = stringListAdapter.fromJson(e.matchedIocDomains) ?: emptyList(),
        dangerousPermissions = stringListAdapter.fromJson(e.dangerousPermissions) ?: emptyList(),
        dangerousComboFlags = stringListAdapter.fromJson(e.dangerousComboFlags) ?: emptyList(),
        totalPermissionCount = e.totalPermissionCount,
        c2Verdict = C2Verdict.fromString(e.c2Verdict),
        c2ConfidenceScore = e.c2ConfidenceScore,
        detectedC2Frameworks = stringListAdapter.fromJson(e.detectedC2Frameworks) ?: emptyList(),
        onnxPredictedClass = e.onnxPredictedClass,
        onnxConfidence = e.onnxConfidence,
        isAnomalyFlagged = e.isAnomalyFlagged,
        lastScannedAt = e.lastScannedAt,
        deepScanAvailable = e.deepScanAvailable,
    )
}
