package com.droidraksha.mobile.ui.screens.applist

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.droidraksha.mobile.data.repository.AppRepository
import com.droidraksha.mobile.domain.model.AppInfo
import com.droidraksha.mobile.domain.model.InstallSource
import com.droidraksha.mobile.domain.model.RiskLevel
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.*
import javax.inject.Inject

data class AppListUiState(
    val allApps: List<AppInfo> = emptyList(),
    val filteredApps: List<AppInfo> = emptyList(),
    val searchQuery: String = "",
    val selectedFilter: String = "ALL", // "ALL" | "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "SAFE" | "SIDELOADED"
    val isLoading: Boolean = false,
)

@HiltViewModel
class AppListViewModel @Inject constructor(
    private val repository: AppRepository
) : ViewModel() {

    private val _uiState = MutableStateFlow(AppListUiState())
    val uiState: StateFlow<AppListUiState> = _uiState.asStateFlow()

    init {
        repository.getAllAppsOrderedByRisk()
            .onEach { apps ->
                _uiState.update { current ->
                    current.copy(
                        allApps = apps,
                        filteredApps = applyFilter(apps, current.searchQuery, current.selectedFilter)
                    )
                }
            }
            .launchIn(viewModelScope)
    }

    fun setInitialFilter(filter: String?) {
        val targetFilter = filter ?: "ALL"
        _uiState.update { current ->
            current.copy(
                selectedFilter = targetFilter,
                filteredApps = applyFilter(current.allApps, current.searchQuery, targetFilter)
            )
        }
    }

    fun onSearchQueryChanged(query: String) {
        _uiState.update { current ->
            current.copy(
                searchQuery = query,
                filteredApps = applyFilter(current.allApps, query, current.selectedFilter)
            )
        }
    }

    fun onFilterSelected(filter: String) {
        _uiState.update { current ->
            current.copy(
                selectedFilter = filter,
                filteredApps = applyFilter(current.allApps, current.searchQuery, filter)
            )
        }
    }

    private fun applyFilter(apps: List<AppInfo>, query: String, filter: String): List<AppInfo> {
        return apps.filter { app ->
            val matchesQuery = query.isBlank() ||
                app.appName.contains(query, ignoreCase = true) ||
                app.packageName.contains(query, ignoreCase = true)

            val matchesFilter = when (filter) {
                "ALL" -> true
                "SIDELOADED" -> app.installSource == InstallSource.SIDELOADED
                else -> app.riskLevel.name == filter
            }

            matchesQuery && matchesFilter
        }
    }
}
