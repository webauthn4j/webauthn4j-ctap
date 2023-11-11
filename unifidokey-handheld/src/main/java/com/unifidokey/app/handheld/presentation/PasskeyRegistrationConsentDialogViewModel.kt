package com.unifidokey.app.handheld.presentation

import android.app.Activity
import android.app.Application
import android.content.Context
import android.content.Intent
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.unifidokey.driver.provider.PasskeyIntentProcessor
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

class PasskeyRegistrationConsentDialogViewModel(application: Application) : AndroidViewModel(application) {
    fun processIntent(activity: Activity, intent: Intent) {
        viewModelScope.launch(Dispatchers.Main) {
            PasskeyIntentProcessor.processIntent(activity, intent)
        }
    }


}