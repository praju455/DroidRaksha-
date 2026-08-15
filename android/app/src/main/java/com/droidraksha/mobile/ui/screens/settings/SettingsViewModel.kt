package com.droidraksha.mobile.ui.screens.settings

import android.content.Context
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.droidraksha.mobile.BuildConfig
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

val Context.dataStore by preferencesDataStore(name = "settings")

data class SettingsUiState(
    val backendUrl: String = BuildConfig.BACKEND_BASE_URL,
    val backgroundScanEnabled: Boolean = true,
    val wifiOnlySync: Boolean = true,
    val scanIntervalHours: Int = 24,
)

@HiltViewModel
class SettingsViewModel @Inject constructor(
    @ApplicationContext private val context: Context
) : ViewModel() {

    private val BACKEND_URL_KEY = stringPreferencesKey("backend_url")
    private val BG_SCAN_KEY = booleanPreferencesKey("bg_scan_enabled")
    private val WIFI_ONLY_KEY = booleanPreferencesKey("wifi_only")

    private val _uiState = MutableStateFlow(SettingsUiState())
    val uiState: StateFlow<SettingsUiState> = _uiState.asStateFlow()

    init {
        viewModelScope.launch {
            context.dataStore.data.collect { prefs ->
                _uiState.update {
                    it.copy(
                        backendUrl = prefs[BACKEND_URL_KEY] ?: BuildConfig.BACKEND_BASE_URL,
                        backgroundScanEnabled = prefs[BG_SCAN_KEY] ?: true,
                        wifiOnlySync = prefs[WIFI_ONLY_KEY] ?: true
                    )
                }
            }
        }
    }

    fun setBackgroundScan(enabled: Boolean) {
        viewModelScope.launch {
            context.dataStore.edit { it[BG_SCAN_KEY] = enabled }
        }
    }

    fun setWifiOnlySync(enabled: Boolean) {
        viewModelScope.launch {
            context.dataStore.edit { it[WIFI_ONLY_KEY] = enabled }
        }
    }

    fun updateBackendUrl(url: String) {
        viewModelScope.launch {
            context.dataStore.edit { it[BACKEND_URL_KEY] = url }
        }
    }
}
