package com.droidraksha.mobile.data.local.dao

import androidx.room.*
import com.droidraksha.mobile.data.local.entity.AppEntity
import kotlinx.coroutines.flow.Flow

/**
 * DAO for the [AppEntity] table.
 *
 * All queries return [Flow] so that Compose screens automatically
 * recompose when the underlying data changes (e.g., after a scan).
 */
@Dao
interface AppDao {

    // ── Upsert all scanned apps atomically ────────────────────────────────
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertAll(apps: List<AppEntity>)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(app: AppEntity)

    // ── Queries for the App List screen ───────────────────────────────────

    /** All apps ordered by risk score descending (highest risk first). */
    @Query("SELECT * FROM apps ORDER BY riskScore DESC")
    fun getAllAppsOrderedByRisk(): Flow<List<AppEntity>>

    /** Apps filtered to a specific risk level. */
    @Query("SELECT * FROM apps WHERE riskLevel = :level ORDER BY riskScore DESC")
    fun getAppsByRiskLevel(level: String): Flow<List<AppEntity>>

    /** Sideloaded apps only. */
    @Query("SELECT * FROM apps WHERE installSource != 'play_store' ORDER BY riskScore DESC")
    fun getSideloadedApps(): Flow<List<AppEntity>>

    /** Apps at MEDIUM risk or above (for deep-scan eligibility). */
    @Query("SELECT * FROM apps WHERE riskScore >= 40 ORDER BY riskScore DESC")
    fun getMediumAndAbove(): Flow<List<AppEntity>>

    // ── Single app queries ────────────────────────────────────────────────

    @Query("SELECT * FROM apps WHERE packageName = :packageName")
    fun getAppByPackage(packageName: String): Flow<AppEntity?>

    @Query("SELECT * FROM apps WHERE packageName = :packageName")
    suspend fun getAppByPackageOnce(packageName: String): AppEntity?

    // ── Dashboard summary counts ──────────────────────────────────────────

    @Query("SELECT COUNT(*) FROM apps WHERE riskLevel = 'CRITICAL'")
    fun getCriticalCount(): Flow<Int>

    @Query("SELECT COUNT(*) FROM apps WHERE riskLevel = 'HIGH'")
    fun getHighCount(): Flow<Int>

    @Query("SELECT COUNT(*) FROM apps WHERE riskLevel = 'MEDIUM'")
    fun getMediumCount(): Flow<Int>

    @Query("SELECT COUNT(*) FROM apps WHERE riskLevel = 'LOW'")
    fun getLowCount(): Flow<Int>

    @Query("SELECT COUNT(*) FROM apps WHERE riskLevel = 'SAFE'")
    fun getSafeCount(): Flow<Int>

    @Query("SELECT COUNT(*) FROM apps")
    fun getTotalCount(): Flow<Int>

    // ── Update deep-scan availability flag ────────────────────────────────

    @Query("UPDATE apps SET deepScanAvailable = 1 WHERE packageName = :packageName")
    suspend fun markDeepScanAvailable(packageName: String)

    // ── Remove apps that have been uninstalled since last scan ────────────

    @Query("DELETE FROM apps WHERE packageName NOT IN (:currentPackages)")
    suspend fun deleteRemovedApps(currentPackages: List<String>)

    @Query("DELETE FROM apps")
    suspend fun clearAll()
}
