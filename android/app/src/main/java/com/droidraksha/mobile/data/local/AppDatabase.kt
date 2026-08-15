package com.droidraksha.mobile.data.local

import androidx.room.Database
import androidx.room.RoomDatabase
import com.droidraksha.mobile.data.local.dao.AppDao
import com.droidraksha.mobile.data.local.dao.DeepScanResultDao
import com.droidraksha.mobile.data.local.dao.ScanHistoryDao
import com.droidraksha.mobile.data.local.entity.AppEntity
import com.droidraksha.mobile.data.local.entity.DeepScanResultEntity
import com.droidraksha.mobile.data.local.entity.ScanHistoryEntity

/**
 * The single Room database for DroidRaksha Mobile.
 *
 * Increment [version] and supply a [Migration] whenever the schema
 * of any entity changes to preserve existing scan data across updates.
 */
@Database(
    entities = [
        AppEntity::class,
        ScanHistoryEntity::class,
        DeepScanResultEntity::class,
    ],
    version = 1,
    exportSchema = true,
)
abstract class AppDatabase : RoomDatabase() {
    abstract fun appDao(): AppDao
    abstract fun scanHistoryDao(): ScanHistoryDao
    abstract fun deepScanResultDao(): DeepScanResultDao
}
