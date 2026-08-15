package com.droidraksha.mobile.data.local.entity

import androidx.room.Entity
import androidx.room.PrimaryKey

/**
 * Records a completed full-device scan session.
 * Allows the Scan History screen to show score trends over time and
 * detect apps that changed risk level after a package update.
 */
@Entity(tableName = "scan_history")
data class ScanHistoryEntity(
    @PrimaryKey(autoGenerate = true)
    val id: Long = 0,

    val scanStartedAt: Long,             // epoch millis
    val scanCompletedAt: Long,           // epoch millis
    val totalAppsScanned: Int,
    val criticalCount: Int,
    val highCount: Int,
    val mediumCount: Int,
    val lowCount: Int,
    val safeCount: Int,
    val newlyFlaggedPackages: String,    // JSON array of package names newly flagged this scan
    val deviceOverallScore: Int,         // 0–100 aggregate device health score
    val triggeredBy: String,             // "manual" | "schedule" | "package_install"
)
