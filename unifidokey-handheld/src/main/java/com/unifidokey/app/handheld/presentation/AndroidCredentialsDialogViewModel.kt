package com.unifidokey.app.handheld.presentation

import android.app.Application
import android.content.Intent
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.unifidokey.app.UnifidoKeyComponent
import com.unifidokey.app.handheld.UnifidoKeyHandHeldApplication
import com.unifidokey.driver.credentials.provider.AndroidCredentialsIntentProcessor
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

class AndroidCredentialsDialogViewModel(application: Application) : AndroidViewModel(application) {

    private val unifidoKeyHandHeldApplication = application as UnifidoKeyHandHeldApplication
    private val unifidoKeyComponent: UnifidoKeyComponent = unifidoKeyHandHeldApplication.unifidoKeyComponent

    fun processIntent(activity: FragmentActivity, intent: Intent) {
        viewModelScope.launch(Dispatchers.Main) {
            AndroidCredentialsIntentProcessor(
                activity,
                unifidoKeyComponent.configManager,
                unifidoKeyComponent.relyingPartyDao,
                unifidoKeyComponent.authenticatorService.ctapAuthenticator
            ).processIntent(activity, intent)
        }
    }
}
