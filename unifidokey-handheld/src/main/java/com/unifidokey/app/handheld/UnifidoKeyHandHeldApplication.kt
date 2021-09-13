package com.unifidokey.app.handheld

import com.unifidokey.app.UnifidoKeyApplicationBase
import com.unifidokey.app.UnifidoKeyComponent
import com.webauthn4j.ctap.authenticator.CachingCredentialSelectionHandler
import com.webauthn4j.ctap.authenticator.CachingUserConsentHandler
import com.unifidokey.app.handheld.presentation.UnifidoKeyCredentialSelectionHandler
import com.unifidokey.app.handheld.presentation.UnifidoKeyUserConsentHandler
import com.unifidokey.core.config.ConfigManager
import com.unifidokey.core.service.AuthenticatorService

class UnifidoKeyHandHeldApplication : UnifidoKeyApplicationBase<UnifidoKeyHandHeldComponent>() {

    companion object {
        const val NFC_FEATURE_FLAG = true
        const val BLE_FEATURE_FLAG = false
        const val BTHID_FEATURE_FLAG = true
    }

    override fun onCreate() {
        super.onCreate()
        initializeAuthenticatorService()
    }

    override fun createUnifidoKeyComponent(): UnifidoKeyHandHeldComponent {
        return DaggerUnifidoKeyHandHeldComponent.builder()
            .unifidoKeyHandHeldModule(UnifidoKeyHandHeldModule(this))
            .build()
    }

    private fun initializeAuthenticatorService() {
        val unifidoKeyComponent: UnifidoKeyComponent = this.unifidoKeyComponent
        val authenticatorService: AuthenticatorService = unifidoKeyComponent.authenticatorService
        val configManager: ConfigManager = unifidoKeyComponent.configManager
        authenticatorService.userConsentHandler = UnifidoKeyUserConsentHandler(this, configManager)
        authenticatorService.credentialSelectionHandler = UnifidoKeyCredentialSelectionHandler(this)
    }


}