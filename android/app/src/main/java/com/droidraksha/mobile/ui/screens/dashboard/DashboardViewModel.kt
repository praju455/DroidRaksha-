package com.droidraksha.mobile.ui.screens.dashboard

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.droidraksha.mobile.data.local.entity.ScanHistoryEntity
import com.droidraksha.mobile.data.repository.AppRepository
import com.droidraksha.mobile.domain.engine.ScanOrchestrator
import com.droidraksha.mobile.domain.model.AppInfo
import com.droidraksha.mobile.domain.model.RiskLevel
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch
import javax.inject.Inject

data class DashboardUiState(
    val isLoading: Boolean = false,
    val isScanning: Boolean = false,
    val scanProgress: Int = 0,
    val scanTotal: Int = 0,
    val currentScanningApp: String = "",
    val totalApps: Int = 0,
    val criticalCount: Int = 0,
    val highCount: Int = 0,
    val mediumCount: Int = 0,
    val lowCount: Int = 0,
    val safeCount: Int = 0,
    val deviceRiskScore: Int = 0,
    val latestSession: ScanHistoryEntity? = null,
    val topThreats: List<AppInfo> = emptyList(),
)

@HiltViewModel
class DashboardViewModel @Inject constructor(
    private val repository: AppRepository,
    private val scanOrchestrator: ScanOrchestrator,
) : ViewModel() {

    private val _uiState = MutableStateFlow(DashboardUiState())
    val uiState: StateFlow<DashboardUiState> = _uiState.asStateFlow()

    init {
        observeData()
    }

    private fun observeData() {
        viewModelScope.launch {
            combine(
                repository.getTotalCount(),
                repository.getCriticalCount(),
                repository.getHighCount(),
                repository.getMediumCount(),
                repository.getLowCount(),
                repository.getSafeCount(),
                repository.getLatestSession(),
                repository.getAllAppsOrderedByRisk()
            ) { total, crit, high, med, low, safe, session, apps ->
                val topThreats = apps.filter { it.riskLevel != RiskLevel.SAFE }.take(5)
                val computedScore = if (total > 0) {
                    val weighted = (crit * 90 + high * 70 + med * 45 + low * 20)
                    (weighted / total).coerceIn(0, 100)
                } else 0

                DashboardUiState(
                    totalApps = total,
                    criticalCount = crit,
                    highCount = high,
                    mediumCount = med,
                    lowCount = low,
                    safeCount = safe,
                    latestSession = session,
                    deviceRiskScore = computedScore,
                    topThreats = topThreats
                )
            }.collect { newState ->
                _uiState.update { current ->
                    newState.copy(
                        isScanning = current.isScanning,
                        scanProgress = current.scanProgress,
                        scanTotal = current.scanTotal,
                        currentScanningApp = current.currentScanningApp
                    )
                }
            }
        }
    }

    fun startScan() {
        if (_uiState.value.isScanning) return
        viewModelScope.launch {
            _uiState.update { it.copy(isScanning = true, scanProgress = 0) }
            scanOrchestrator.runFullScan(
                onProgress = { progress ->
                    _uiState.update {
                        it.copy(
                            scanProgress = progress.current,
                            scanTotal = progress.total,
                            currentScanningApp = progress.currentAppName
                        )
                    }
                },
                triggeredBy = "manual"
            )
            _uiState.update { it.copy(isScanning = false) }
        }
    }
}
