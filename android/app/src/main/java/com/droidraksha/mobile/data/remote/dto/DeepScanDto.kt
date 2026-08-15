package com.droidraksha.mobile.data.remote.dto

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

@JsonClass(generateAdapter = true)
data class DeepScanRequest(
    @Json(name = "package_name") val packageName: String,
    @Json(name = "hashes") val hashes: List<String> = emptyList(),
    @Json(name = "extracted_ips") val extractedIps: List<String> = emptyList(),
    @Json(name = "extracted_urls") val extractedUrls: List<String> = emptyList(),
    @Json(name = "local_risk_score") val localRiskScore: Int = 0,
)

@JsonClass(generateAdapter = true)
data class DeepScanResponse(
    @Json(name = "package_name") val packageName: String,
    @Json(name = "deep_verdict") val deepVerdict: String,
    @Json(name = "confidence") val confidence: Float,
    @Json(name = "narrative") val narrative: String,
    @Json(name = "recommended_action") val recommendedAction: String = "UNINSTALL",
    @Json(name = "action_detail") val actionDetail: String = "",
    @Json(name = "virustotal_detections") val vtDetections: Int = 0,
    @Json(name = "virustotal_engines") val vtEngines: Int = 0,
    @Json(name = "abuseipdb_confidence") val abuseConfidence: Int = 0,
    @Json(name = "malbert_label") val malBertLabel: String = "Unknown",
    @Json(name = "backend_risk_score") val backendRiskScore: Int = 0,
    @Json(name = "backend_risk_level") val backendRiskLevel: String = "HIGH",
)
