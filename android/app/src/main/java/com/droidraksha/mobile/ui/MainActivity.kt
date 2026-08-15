package com.droidraksha.mobile.ui

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.Surface
import androidx.compose.ui.Modifier
import androidx.navigation.compose.rememberNavController
import com.droidraksha.mobile.ui.navigation.AppNavigation
import com.droidraksha.mobile.ui.theme.DroidRakshaTheme
import com.droidraksha.mobile.ui.theme.ShieldNavyDark
import dagger.hilt.android.AndroidEntryPoint

@AndroidEntryPoint
class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            DroidRakshaTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = ShieldNavyDark
                ) {
                    val navController = rememberNavController()
                    AppNavigation(navController = navController)
                }
            }
        }
    }
}
