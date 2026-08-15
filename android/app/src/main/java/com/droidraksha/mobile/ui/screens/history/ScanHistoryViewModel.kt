package com.droidraksha.mobile.ui.screens.history

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.droidraksha.mobile.data.local.entity.ScanHistoryEntity
import com.droidraksha.mobile.data.repository.AppRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.*
import javax.inject.Inject

data class ScanHistoryUiState(
    val sessions: List<ScanHistoryEntity> = emptyList(),
    val isLoading: Boolean = false,
)

@HiltViewModel
class ScanHistoryViewModel @Inject constructor(
    private val repository: AppRepository
) : ViewModel() {

    private val _uiState = MutableStateFlow(ScanHistoryUiState())
    val uiState: StateFlow<ScanHistoryUiState> = _uiState.asStateFlow()

    init {
        repository.getAllSessions()
            .onEach { sessions ->
                _uiState.update { it.copy(sessions = sessions, isLoading = false) }
            }
            .launchIn(viewModelScope)
    }
}
