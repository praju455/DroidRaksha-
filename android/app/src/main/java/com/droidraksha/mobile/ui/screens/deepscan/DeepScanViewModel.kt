package com.droidraksha.mobile.ui.screens.deepscan

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.droidraksha.mobile.data.local.entity.DeepScanResultEntity
import com.droidraksha.mobile.data.repository.AppRepository
import com.droidraksha.mobile.data.repository.DeepScanRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch
import javax.inject.Inject

data class DeepScanUiState(
    val packageName: String = "",
    val appName: String = "",
    val isLoading: Boolean = true,
    val result: DeepScanResultEntity? = null,
    val errorMessage: String? = null,
)

@HiltViewModel
class DeepScanViewModel @Inject constructor(
    private val deepScanRepository: DeepScanRepository,
    private val appRepository: AppRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(DeepScanUiState())
    val uiState: StateFlow<DeepScanUiState> = _uiState.asStateFlow()

    fun triggerDeepScan(packageName: String) {
        _uiState.update { it.copy(packageName = packageName, isLoading = true, errorMessage = null) }

        viewModelScope.launch {
            val app = appRepository.getAppByPackage(packageName).firstOrNull()
            val appName = app?.appName ?: packageName
            val localScore = app?.riskScore ?: 50

            _uiState.update { it.copy(appName = appName) }

            val res = deepScanRepository.executeDeepScan(
                packageName = packageName,
                localRiskScore = localScore
            )

            res.fold(
                onSuccess = { entity ->
                    _uiState.update { it.copy(result = entity, isLoading = false) }
                },
                onFailure = { err ->
                    _uiState.update { it.copy(errorMessage = err.localizedMessage, isLoading = false) }
                }
            )
        }
    }
}
