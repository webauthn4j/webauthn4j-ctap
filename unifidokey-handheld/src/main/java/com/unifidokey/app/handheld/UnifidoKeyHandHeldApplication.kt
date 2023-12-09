package com.unifidokey.app.handheld

import com.unifidokey.BuildConfig
import com.unifidokey.app.UnifidoKeyApplicationBase
import com.unifidokey.app.UnifidoKeyComponent
import com.unifidokey.app.handheld.presentation.UnifidoKeyCredentialSelectionHandler
import com.unifidokey.app.handheld.presentation.UnifidoKeyGetAssertionConsentRequestHandler
import com.unifidokey.app.handheld.presentation.UnifidoKeyMakeCredentialConsentRequestHandler
import com.unifidokey.core.config.ConfigManager
import com.unifidokey.core.service.AuthenticatorService

class UnifidoKeyHandHeldApplication : UnifidoKeyApplicationBase<UnifidoKeyHandHeldComponent>() {

    companion object {
        const val NFC_FEATURE_FLAG = true
        const val BLE_FEATURE_FLAG = false
        const val BTHID_FEATURE_FLAG = false

        val isOssFlavor : Boolean
            get() = BuildConfig.FLAVOR == "oss"
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
        authenticatorService.makeCredentialConsentRequestHandler = UnifidoKeyMakeCredentialConsentRequestHandler(this, configManager)
        authenticatorService.getAssertionConsentRequestHandler = UnifidoKeyGetAssertionConsentRequestHandler(this, configManager)
        authenticatorService.credentialSelectionHandler = UnifidoKeyCredentialSelectionHandler(this)
    }
}
