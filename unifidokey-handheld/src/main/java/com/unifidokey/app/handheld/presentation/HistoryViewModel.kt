package com.unifidokey.app.handheld.presentation

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.LiveData
import com.unifidokey.app.handheld.UnifidoKeyHandHeldApplication
import com.unifidokey.app.handheld.UnifidoKeyHandHeldComponent
import com.unifidokey.core.service.AuthenticatorService
import com.webauthn4j.ctap.authenticator.event.Event

class HistoryViewModel(application: Application) : AndroidViewModel(application) {

    private var authenticatorService: AuthenticatorService
    private var unifidoKeyComponent: UnifidoKeyHandHeldComponent
    val events: LiveData<List<Event>>
        get() = authenticatorService.events


    init {
        val unifidoKeyHandHeldApplication = application as UnifidoKeyHandHeldApplication
        unifidoKeyComponent = unifidoKeyHandHeldApplication.unifidoKeyComponent
        authenticatorService = unifidoKeyComponent.authenticatorService
    }
}