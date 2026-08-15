package com.droidraksha.mobile

import android.app.Application
import androidx.hilt.work.HiltWorkerFactory
import androidx.work.Configuration
import dagger.hilt.android.HiltAndroidApp
import javax.inject.Inject

/**
 * DroidRaksha Application class.
 *
 * Serves as the Hilt DI entry point and provides custom WorkManager
 * configuration so Hilt-injected workers resolve dependencies correctly.
 */
@HiltAndroidApp
class DroidRakshaApp : Application(), Configuration.Provider {

    @Inject
    lateinit var workerFactory: HiltWorkerFactory

    override val workManagerConfiguration: Configuration
        get() = Configuration.Builder()
            .setWorkerFactory(workerFactory)
            .setMinimumLoggingLevel(android.util.Log.DEBUG)
            .build()
}
