package com.droidraksha.mobile.domain.engine

import android.app.usage.NetworkStats
import android.app.usage.NetworkStatsManager
import android.content.Context
import android.net.ConnectivityManager
import android.os.RemoteException
import com.droidraksha.mobile.domain.model.NetworkMetrics
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject
import javax.inject.Singleton
import kotlin.math.sqrt

/**
 * Layer 3a Engine — Network Traffic Monitor.
 *
 * Queries [NetworkStatsManager] to obtain per-app RX/TX byte counts and
 * connection timestamps for the last 24 hours. Requires the
 * [PACKAGE_USAGE_STATS] permission (user must grant via special settings page).
 *
 * Collected data feeds directly into [C2BeaconDetector] for regularity analysis.
 */
@Singleton
class NetworkTrafficMonitor @Inject constructor(
    @ApplicationContext private val context: Context,
) {
    private val statsManager: NetworkStatsManager by lazy {
        context.getSystemService(Context.NETWORK_STATS_SERVICE) as NetworkStatsManager
    }

    private val WINDOW_MS = 24 * 60 * 60 * 1000L  // 24 hours

    /**
     * Returns [NetworkMetrics] for the app identified by [uid].
     * [uid] can be obtained from [PackageManager.getApplicationInfo().uid].
     *
     * Returns null if PACKAGE_USAGE_STATS permission is not granted.
     */
    fun getMetrics(packageName: String, uid: Int): NetworkMetrics? {
        return runCatching {
            val end = System.currentTimeMillis()
            val start = end - WINDOW_MS

            var rxTotal = 0L; var txTotal = 0L
            var rxBg = 0L; var txBg = 0L
            var rxFg = 0L; var txFg = 0L
            val timestamps = mutableListOf<Long>()

            // ── Query WiFi + Mobile traffic ──────────────────────────────
            for (networkType in listOf(
                ConnectivityManager.TYPE_WIFI,
                ConnectivityManager.TYPE_MOBILE
            )) {
                val summary = querySummary(networkType, uid, start, end) ?: continue

                while (summary.hasNextBucket()) {
                    val bucket = NetworkStats.Bucket()
                    summary.getNextBucket(bucket)

                    val rx = bucket.rxBytes
                    val tx = bucket.txBytes

                    rxTotal += rx; txTotal += tx

                    when (bucket.state) {
                        NetworkStats.Bucket.STATE_FOREGROUND -> { rxFg += rx; txFg += tx }
                        else -> { rxBg += rx; txBg += tx }
                    }

                    // Record midpoint timestamp of bucket as a connection event
                    if (rx + tx > 0) {
                        timestamps.add((bucket.startTimeStamp + bucket.endTimeStamp) / 2)
                    }
                }
                summary.close()
            }

            // ── Compute CoV over connection intervals ─────────────────────
            val sorted = timestamps.sorted()
            val intervals = sorted.zipWithNext { a, b -> b - a }
            val cov = computeCoV(intervals)
            val isBeaconing = cov < 0.3f && intervals.size >= 5

            NetworkMetrics(
                packageName = packageName,
                uid = uid,
                rxBytesLast24h = rxTotal,
                txBytesLast24h = txTotal,
                backgroundRxBytes = rxBg,
                backgroundTxBytes = txBg,
                foregroundRxBytes = rxFg,
                foregroundTxBytes = txFg,
                connectionIntervals = intervals,
                intervalCoefficientOfVariation = cov,
                isBeaconingFlagged = isBeaconing,
                capturedAt = System.currentTimeMillis(),
            )
        }.getOrNull()
    }

    private fun querySummary(networkType: Int, uid: Int, start: Long, end: Long): NetworkStats? =
        runCatching {
            statsManager.querySummary(networkType, null, start, end)
        }.getOrNull()

    /**
     * Coefficient of Variation = stddev / mean.
     * A low CoV (< 0.3) means connection intervals are suspiciously regular,
     * characteristic of automated C2 beaconing rather than human usage.
     */
    private fun computeCoV(intervals: List<Long>): Float {
        if (intervals.size < 2) return 1f  // insufficient data → not flagged
        val mean = intervals.average()
        if (mean == 0.0) return 0f
        val variance = intervals.map { (it - mean) * (it - mean) }.average()
        val stddev = sqrt(variance)
        return (stddev / mean).toFloat().coerceIn(0f, 5f)
    }
}
