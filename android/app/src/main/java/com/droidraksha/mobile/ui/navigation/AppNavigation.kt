package com.droidraksha.mobile.ui.navigation

import androidx.compose.runtime.Composable
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import com.droidraksha.mobile.ui.screens.appdetail.AppDetailScreen
import com.droidraksha.mobile.ui.screens.appdetail.AppDetailViewModel
import com.droidraksha.mobile.ui.screens.applist.AppListScreen
import com.droidraksha.mobile.ui.screens.applist.AppListViewModel
import com.droidraksha.mobile.ui.screens.dashboard.DashboardScreen
import com.droidraksha.mobile.ui.screens.dashboard.DashboardViewModel
import com.droidraksha.mobile.ui.screens.deepscan.DeepScanResultScreen
import com.droidraksha.mobile.ui.screens.deepscan.DeepScanViewModel
import com.droidraksha.mobile.ui.screens.history.ScanHistoryScreen
import com.droidraksha.mobile.ui.screens.history.ScanHistoryViewModel
import com.droidraksha.mobile.ui.screens.onboarding.OnboardingScreen
import com.droidraksha.mobile.ui.screens.settings.SettingsScreen
import com.droidraksha.mobile.ui.screens.settings.SettingsViewModel

@Composable
fun AppNavigation(
    navController: NavHostController,
    startDestination: String = Screen.Onboarding.route
) {
    NavHost(
        navController = navController,
        startDestination = startDestination
    ) {
        composable(Screen.Onboarding.route) {
            OnboardingScreen(
                onAcceptAndContinue = {
                    navController.navigate(Screen.Dashboard.route) {
                        popUpTo(Screen.Onboarding.route) { inclusive = true }
                    }
                }
            )
        }

        composable(Screen.Dashboard.route) {
            val viewModel: DashboardViewModel = hiltViewModel()
            DashboardScreen(
                viewModel = viewModel,
                onNavigateToAppList = { filter ->
                    navController.navigate(
                        if (filter != null) "app_list?filter=$filter" else Screen.AppList.route
                    )
                },
                onNavigateToAppDetail = { pkg ->
                    navController.navigate(Screen.AppDetail.createRoute(pkg))
                },
                onNavigateToHistory = {
                    navController.navigate(Screen.ScanHistory.route)
                },
                onNavigateToSettings = {
                    navController.navigate(Screen.Settings.route)
                }
            )
        }

        composable(
            route = "app_list?filter={filter}",
            arguments = listOf(navArgument("filter") {
                type = NavType.StringType
                nullable = true
                defaultValue = null
            })
        ) { backStackEntry ->
            val filter = backStackEntry.arguments?.getString("filter")
            val viewModel: AppListViewModel = hiltViewModel()
            viewModel.setInitialFilter(filter)
            AppListScreen(
                viewModel = viewModel,
                onNavigateBack = { navController.popBackStack() },
                onNavigateToAppDetail = { pkg ->
                    navController.navigate(Screen.AppDetail.createRoute(pkg))
                }
            )
        }

        composable(
            route = Screen.AppDetail.route,
            arguments = listOf(navArgument("packageName") { type = NavType.StringType })
        ) { backStackEntry ->
            val pkg = backStackEntry.arguments?.getString("packageName") ?: ""
            val viewModel: AppDetailViewModel = hiltViewModel()
            AppDetailScreen(
                packageName = pkg,
                viewModel = viewModel,
                onNavigateBack = { navController.popBackStack() },
                onNavigateToDeepScan = { p ->
                    navController.navigate(Screen.DeepScanResult.createRoute(p))
                }
            )
        }

        composable(
            route = Screen.DeepScanResult.route,
            arguments = listOf(navArgument("packageName") { type = NavType.StringType })
        ) { backStackEntry ->
            val pkg = backStackEntry.arguments?.getString("packageName") ?: ""
            val viewModel: DeepScanViewModel = hiltViewModel()
            DeepScanResultScreen(
                packageName = pkg,
                viewModel = viewModel,
                onNavigateBack = { navController.popBackStack() }
            )
        }

        composable(Screen.ScanHistory.route) {
            val viewModel: ScanHistoryViewModel = hiltViewModel()
            ScanHistoryScreen(
                viewModel = viewModel,
                onNavigateBack = { navController.popBackStack() }
            )
        }

        composable(Screen.Settings.route) {
            val viewModel: SettingsViewModel = hiltViewModel()
            SettingsScreen(
                viewModel = viewModel,
                onNavigateBack = { navController.popBackStack() }
            )
        }
    }
}
