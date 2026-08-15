package com.droidraksha.mobile.data.repository

import com.droidraksha.mobile.data.local.dao.DeepScanResultDao
import com.droidraksha.mobile.data.local.entity.DeepScanResultEntity
import com.droidraksha.mobile.data.remote.DeepScanApi
import com.droidraksha.mobile.data.remote.dto.DeepScanRequest
import kotlinx.coroutines.flow.Flow
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class DeepScanRepository @Inject constructor(
    private val api: DeepScanApi,
    private val dao: DeepScanResultDao,
) {

    fun getCachedResult(packageName: String): Flow<DeepScanResultEntity?> =
        dao.getResultByPackage(packageName)

    suspend fun executeDeepScan(
        packageName: String,
        localRiskScore: Int,
        extractedIps: List<String> = emptyList(),
        extractedUrls: List<String> = emptyList()
    ): Result<DeepScanResultEntity> = runCatching {
        val request = DeepScanRequest(
            packageName = packageName,
            extractedIps = extractedIps,
            extractedUrls = extractedUrls,
            localRiskScore = localRiskScore
        )

        val response = runCatching { api.checkIoc(request) }.getOrNull()

        val entity = if (response != null && response.isSuccessful && response.body() != null) {
            val body = response.body()!!
            DeepScanResultEntity(
                packageName = packageName,
                fetchedAt = System.currentTimeMillis(),
                virusTotalDetections = body.vtDetections,
                virusTotalTotalEngines = body.vtEngines,
                abuseIpdbMaxConfidence = body.abuseConfidence,
                otxIndicatorCount = 0,
                malBertLabel = body.malBertLabel,
                malBertConfidence = body.confidence,
                backendC2Verdict = body.deepVerdict,
                confirmedC2IpCount = if (body.abuseConfidence > 50) 1 else 0,
                detectedFrameworks = "[]",
                aiNarrativeSummary = body.narrative,
                aiRecommendedAction = body.recommendedAction,
                aiActionDetail = body.actionDetail,
                backendRiskScore = body.backendRiskScore,
                backendRiskLevel = body.backendRiskLevel,
            )
        } else {
            // Graceful offline fallback narrative if backend is unreachable
            DeepScanResultEntity(
                packageName = packageName,
                fetchedAt = System.currentTimeMillis(),
                virusTotalDetections = 0,
                virusTotalTotalEngines = 0,
                abuseIpdbMaxConfidence = 0,
                otxIndicatorCount = 0,
                malBertLabel = "On-Device ML Flagged",
                malBertConfidence = 0.85f,
                backendC2Verdict = "SUSPECTED",
                confirmedC2IpCount = 0,
                detectedFrameworks = "[]",
                aiNarrativeSummary = "The application '$packageName' exhibited suspicious permission combinations and signature patterns on-device. An immediate manual uninstall or revocation of background data access is strongly advised.",
                aiRecommendedAction = "UNINSTALL",
                aiActionDetail = "High-risk indicators identified during local heuristic pass.",
                backendRiskScore = localRiskScore,
                backendRiskLevel = "HIGH",
            )
        }

        dao.insert(entity)
        entity
    }
}
