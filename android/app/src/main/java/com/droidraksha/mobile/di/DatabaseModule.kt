package com.droidraksha.mobile.di

import android.content.Context
import androidx.room.Room
import com.droidraksha.mobile.data.local.AppDatabase
import com.droidraksha.mobile.data.local.dao.AppDao
import com.droidraksha.mobile.data.local.dao.DeepScanResultDao
import com.droidraksha.mobile.data.local.dao.ScanHistoryDao
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/**
 * Hilt module that provides the Room [AppDatabase] and its DAOs as
 * application-scoped singletons. Hilt will inject these wherever needed.
 */
@Module
@InstallIn(SingletonComponent::class)
object DatabaseModule {

    @Provides
    @Singleton
    fun provideDatabase(@ApplicationContext context: Context): AppDatabase =
        Room.databaseBuilder(
            context,
            AppDatabase::class.java,
            "droidraksha.db"
        )
            .fallbackToDestructiveMigration()   // safe during development; add Migrations before release
            .build()

    @Provides
    fun provideAppDao(db: AppDatabase): AppDao = db.appDao()

    @Provides
    fun provideScanHistoryDao(db: AppDatabase): ScanHistoryDao = db.scanHistoryDao()

    @Provides
    fun provideDeepScanResultDao(db: AppDatabase): DeepScanResultDao = db.deepScanResultDao()
}
