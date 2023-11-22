package com.unifidokey.app.handheld.presentation

import android.app.Activity
import android.app.Application
import android.content.Intent
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.unifidokey.app.UnifidoKeyComponent
import com.unifidokey.app.handheld.UnifidoKeyHandHeldApplication
import com.unifidokey.driver.credentials.provider.AndroidCredentialsIntentProcessor
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

class PasskeyRegistrationConsentDialogViewModel(application: Application) : AndroidViewModel(application) {

    private val unifidoKeyHandHeldApplication = application as UnifidoKeyHandHeldApplication
    private val unifidoKeyComponent: UnifidoKeyComponent = unifidoKeyHandHeldApplication.unifidoKeyComponent

    fun processIntent(activity: Activity, intent: Intent) {
        viewModelScope.launch(Dispatchers.Main) {
            AndroidCredentialsIntentProcessor(activity, unifidoKeyComponent.configManager, unifidoKeyComponent.authenticatorService.ctapAuthenticator).processIntent(activity, intent)
        }
    }
}
