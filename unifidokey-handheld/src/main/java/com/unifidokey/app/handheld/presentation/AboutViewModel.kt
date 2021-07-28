package com.unifidokey.app.handheld.presentation

import androidx.lifecycle.ViewModel
import com.unifidokey.BuildConfig

class AboutViewModel : ViewModel() {
    val version: String
        get() = BuildConfig.VERSION_NAME
}