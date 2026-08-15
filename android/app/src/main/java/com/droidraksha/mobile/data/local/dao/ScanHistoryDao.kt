package com.droidraksha.mobile.data.local.dao

import androidx.room.*
import com.droidraksha.mobile.data.local.entity.ScanHistoryEntity
import kotlinx.coroutines.flow.Flow

@Dao
interface ScanHistoryDao {

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(entry: ScanHistoryEntity): Long

    /** All scan sessions, newest first — used by the Scan History screen. */
    @Query("SELECT * FROM scan_history ORDER BY scanCompletedAt DESC")
    fun getAllSessions(): Flow<List<ScanHistoryEntity>>

    /** Most recent completed scan — used by the Dashboard screen. */
    @Query("SELECT * FROM scan_history ORDER BY scanCompletedAt DESC LIMIT 1")
    fun getLatestSession(): Flow<ScanHistoryEntity?>

    /** Keep only the last N scan records to bound DB growth. */
    @Query("""
        DELETE FROM scan_history 
        WHERE id NOT IN (
            SELECT id FROM scan_history ORDER BY scanCompletedAt DESC LIMIT :keepCount
        )
    """)
    suspend fun pruneOldSessions(keepCount: Int = 30)
}
