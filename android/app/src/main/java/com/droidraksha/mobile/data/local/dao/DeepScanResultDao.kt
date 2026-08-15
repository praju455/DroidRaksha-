package com.droidraksha.mobile.data.local.dao

import androidx.room.*
import com.droidraksha.mobile.data.local.entity.DeepScanResultEntity
import kotlinx.coroutines.flow.Flow

@Dao
interface DeepScanResultDao {

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(result: DeepScanResultEntity)

    @Query("SELECT * FROM deep_scan_results WHERE packageName = :packageName")
    fun getResultByPackage(packageName: String): Flow<DeepScanResultEntity?>

    @Query("SELECT * FROM deep_scan_results WHERE packageName = :packageName")
    suspend fun getResultByPackageOnce(packageName: String): DeepScanResultEntity?

    @Query("DELETE FROM deep_scan_results WHERE packageName = :packageName")
    suspend fun deleteByPackage(packageName: String)

    /** Evict deep scan cache entries older than 24 hours. */
    @Query("DELETE FROM deep_scan_results WHERE fetchedAt < :cutoffEpochMillis")
    suspend fun evictStale(cutoffEpochMillis: Long)
}
