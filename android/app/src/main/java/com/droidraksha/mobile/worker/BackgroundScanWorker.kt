package com.droidraksha.mobile.worker

import android.content.Context
import androidx.hilt.work.HiltWorker
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import com.droidraksha.mobile.domain.engine.ScanOrchestrator
import dagger.assisted.Assisted
import dagger.assisted.AssistedInject

@HiltWorker
class BackgroundScanWorker @AssistedInject constructor(
    @Assisted private val context: Context,
    @Assisted private val params: WorkerParameters,
    private val scanOrchestrator: ScanOrchestrator,
    private val notificationHelper: NotificationHelper,
) : CoroutineWorker(context, params) {

    override suspend fun doWork(): Result {
        return runCatching {
            val scanResult = scanOrchestrator.runFullScan(
                triggeredBy = "schedule"
            )

            if (scanResult is ScanOrchestrator.ScanState.Completed) {
                if (scanResult.criticalCount > 0 || scanResult.highCount > 0) {
                    notificationHelper.showThreatAlert(
                        criticalCount = scanResult.criticalCount,
                        highCount = scanResult.highCount
                    )
                }
            }
            Result.success()
        }.getOrElse {
            Result.retry()
        }
    }
}
