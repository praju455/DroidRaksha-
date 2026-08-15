package com.droidraksha.mobile.worker

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import com.droidraksha.mobile.domain.engine.ScanOrchestrator
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import javax.inject.Inject

@AndroidEntryPoint
class PackageInstallReceiver : BroadcastReceiver() {

    @Inject
    lateinit var scanOrchestrator: ScanOrchestrator

    @Inject
    lateinit var notificationHelper: NotificationHelper

    override fun onReceive(context: Context?, intent: Intent?) {
        if (intent == null || context == null) return

        val action = intent.action
        if (action == Intent.ACTION_PACKAGE_ADDED || action == Intent.ACTION_PACKAGE_REPLACED) {
            val packageName = intent.data?.schemeSpecificPart ?: return

            // Run asynchronous single-app scan on new install
            CoroutineScope(Dispatchers.Default).launch {
                val res = scanOrchestrator.scanSingleApp(packageName)
                if (res is ScanOrchestrator.ScanState.Completed) {
                    if (res.criticalCount > 0 || res.highCount > 0) {
                        notificationHelper.showThreatAlert(res.criticalCount, res.highCount)
                    }
                }
            }
        }
    }
}
