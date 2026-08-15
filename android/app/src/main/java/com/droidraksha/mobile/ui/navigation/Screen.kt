package com.droidraksha.mobile.ui.navigation

sealed class Screen(val route: String) {
    object Onboarding : Screen("onboarding")
    object Dashboard : Screen("dashboard")
    object AppList : Screen("app_list")
    object AppDetail : Screen("app_detail/{packageName}") {
        fun createRoute(packageName: String) = "app_detail/$packageName"
    }
    object DeepScanResult : Screen("deep_scan/{packageName}") {
        fun createRoute(packageName: String) = "deep_scan/$packageName"
    }
    object ScanHistory : Screen("scan_history")
    object Settings : Screen("settings")
}
