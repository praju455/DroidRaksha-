package com.droidraksha.mobile.ui.screens.appdetail

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.droidraksha.mobile.data.repository.AppRepository
import com.droidraksha.mobile.domain.model.AppInfo
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.*
import javax.inject.Inject

data class AppDetailUiState(
    val app: AppInfo? = null,
    val isLoading: Boolean = true,
)

@HiltViewModel
class AppDetailViewModel @Inject constructor(
    private val repository: AppRepository
) : ViewModel() {

    private val _uiState = MutableStateFlow(AppDetailUiState())
    val uiState: StateFlow<AppDetailUiState> = _uiState.asStateFlow()

    fun loadApp(packageName: String) {
        repository.getAppByPackage(packageName)
            .onEach { app ->
                _uiState.update { it.copy(app = app, isLoading = false) }
            }
            .launchIn(viewModelScope)
    }
}
