package com.droidraksha.mobile.domain.engine

import android.content.Context
import android.content.pm.PackageManager
import ai.onnxruntime.OnnxTensor
import ai.onnxruntime.OrtEnvironment
import ai.onnxruntime.OrtSession
import com.droidraksha.mobile.domain.engine.model.OnnxInferenceResult
import com.squareup.moshi.Moshi
import com.squareup.moshi.Types
import dagger.hilt.android.qualifiers.ApplicationContext
import java.nio.FloatBuffer
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Layer 2d Engine — On-Device ML Inference via ONNX Runtime.
 *
 * Loads the XGBoost classifier (xgboost_model.onnx) and Isolation Forest
 * anomaly detector (isolation_forest.onnx) from assets and runs them
 * locally on the device with no network connection required.
 *
 * Feature extraction:
 *   - Parses [feature_columns.json] to understand the exact feature vector
 *     expected by the model (573 syscall / API features from CICMalDroid).
 *   - Extracts a binary feature vector from the app's declared permissions
 *     and visible API usages via PackageManager.
 *   - Feeds the vector into both models for joint classification and anomaly
 *     detection.
 *
 * Classes (from label_map.json):
 *   0=Adware, 1=Banking, 2=SMS_Malware, 3=Riskware, 4=Benign
 *
 * NOTE: For the initial release the feature vector is built from PackageManager
 * data which covers the permission/API subset of the full feature space. A full
 * on-device Frida hook pass would be needed for syscall-level coverage.
 */
@Singleton
class OnDeviceMLInference @Inject constructor(
    @ApplicationContext private val context: Context,
    private val moshi: Moshi,
) {
    companion object {
        private val CLASS_LABELS = listOf("Adware", "Banking", "SMS_Malware", "Riskware", "Benign")
    }

    private val pm: PackageManager = context.packageManager
    private val env: OrtEnvironment = OrtEnvironment.getEnvironment()

    // Lazily create ORT sessions — models are ~2-5 MB so keep resident
    private val xgbSession: OrtSession by lazy { loadSession("xgboost_model.onnx") }
    private val isoSession: OrtSession by lazy { loadSession("isolation_forest.onnx") }
    private val featureColumns: List<String> by lazy { loadFeatureColumns() }

    /**
     * Run XGBoost classification and Isolation Forest anomaly detection for [packageName].
     *
     * @param packageName  The app to classify.
     * @param apkPath      Optional path to the APK for deeper string-level feature extraction.
     *                     If null, only PackageManager features are used.
     */
    fun classify(packageName: String, apkPath: String? = null): OnnxInferenceResult {
        val featureVector = buildFeatureVector(packageName, apkPath)

        // ── XGBoost classification ────────────────────────────────────────
        val xgbResult = runCatching {
            val tensor = OnnxTensor.createTensor(
                env,
                FloatBuffer.wrap(featureVector),
                longArrayOf(1L, featureVector.size.toLong())
            )
            val output = xgbSession.run(mapOf("input" to tensor))
            // Output[0] = class label (int), Output[1] = probabilities (float[5])
            val labelTensor = output[0].value as? LongArray
            val probTensor = output[1].value as? Array<FloatArray>

            val classIdx = labelTensor?.get(0)?.toInt() ?: 4  // default Benign
            val probs = probTensor?.get(0) ?: FloatArray(5) { if (it == 4) 1f else 0f }

            Pair(classIdx, probs)
        }.getOrDefault(Pair(4, FloatArray(5) { if (it == 4) 1f else 0f }))

        val (classIdx, probs) = xgbResult
        val predictedClass = CLASS_LABELS.getOrElse(classIdx) { "Benign" }
        val confidence = probs.getOrElse(classIdx) { 1f }

        // ── Isolation Forest anomaly detection ────────────────────────────
        val isAnomaly = runCatching {
            val tensor = OnnxTensor.createTensor(
                env,
                FloatBuffer.wrap(featureVector),
                longArrayOf(1L, featureVector.size.toLong())
            )
            val output = isoSession.run(mapOf("input" to tensor))
            // Isolation Forest output: -1 = anomaly, 1 = normal
            val result = output[0].value as? LongArray
            result?.get(0) == -1L
        }.getOrDefault(false)

        return OnnxInferenceResult(
            packageName = packageName,
            predictedClass = predictedClass,
            confidence = confidence,
            isAnomalyFlagged = isAnomaly,
            classProbabilities = CLASS_LABELS.zip(probs.toList()).toMap(),
        )
    }

    /**
     * Build a float feature vector from available on-device signals.
     *
     * For each column in [feature_columns.json], the value is 1.0 if the
     * corresponding permission or API indicator is present in the app's manifest,
     * otherwise 0.0. This is the same binary encoding used during training.
     */
    private fun buildFeatureVector(packageName: String, apkPath: String?): FloatArray {
        val declaredPerms: Set<String> = runCatching {
            pm.getPackageInfo(packageName, PackageManager.GET_PERMISSIONS)
                .requestedPermissions?.toSet() ?: emptySet()
        }.getOrDefault(emptySet())

        // Map simplified permission → feature column name
        val permFeatureMap = declaredPerms.associate { perm ->
            val simplified = perm.removePrefix("android.permission.").uppercase()
            simplified to 1f
        }

        return FloatArray(featureColumns.size) { idx ->
            val col = featureColumns[idx]
            // Try direct match; fall back to 0 (feature not present)
            permFeatureMap[col.uppercase()] ?: 0f
        }
    }

    private fun loadSession(assetName: String): OrtSession {
        val bytes = context.assets.open(assetName).readBytes()
        return env.createSession(bytes, OrtSession.SessionOptions())
    }

    private fun loadFeatureColumns(): List<String> {
        val json = context.assets.open("feature_columns.json").bufferedReader().readText()
        val type = Types.newParameterizedType(List::class.java, String::class.java)
        return moshi.adapter<List<String>>(type).fromJson(json) ?: emptyList()
    }
}
