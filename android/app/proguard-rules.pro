# DroidRaksha — ProGuard Rules

# Keep Hilt-generated classes
-keep class dagger.hilt.** { *; }
-keep class javax.inject.** { *; }

# Keep Room entity classes (annotated with @Entity)
-keep @androidx.room.Entity class * { *; }

# Keep Moshi adapters
-keep class com.squareup.moshi.** { *; }
-keepclassmembers class * {
    @com.squareup.moshi.FromJson *;
    @com.squareup.moshi.ToJson *;
}

# Keep data classes used by Moshi (domain models serialized to/from JSON)
-keep class com.droidraksha.mobile.domain.model.** { *; }
-keep class com.droidraksha.mobile.data.local.entity.** { *; }
-keep class com.droidraksha.mobile.data.remote.dto.** { *; }

# ONNX Runtime
-keep class ai.onnxruntime.** { *; }

# Retrofit / OkHttp
-keepattributes Signature, InnerClasses, EnclosingMethod
-keepattributes RuntimeVisibleAnnotations, RuntimeVisibleParameterAnnotations
-keepclassmembers,allowshrinking,allowobfuscation interface * {
    @retrofit2.http.* <methods>;
}

# WorkManager
-keep class androidx.work.** { *; }
-keep class com.droidraksha.mobile.worker.** { *; }

# Kotlin coroutines
-keepnames class kotlinx.coroutines.internal.MainDispatcherFactory {}
-keepnames class kotlinx.coroutines.CoroutineExceptionHandler {}
