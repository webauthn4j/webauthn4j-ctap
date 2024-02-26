package com.unifidokey.app.handheld

import com.unifidokey.BuildConfig
import com.unifidokey.app.UnifidoKeyApplicationBase
import com.unifidokey.app.UnifidoKeyComponent
import com.unifidokey.app.handheld.presentation.UnifidoKeyCredentialSelectionHandler
import com.unifidokey.app.handheld.presentation.CtapAuthenticatorUserVerificationHandler
import com.unifidokey.core.config.ConfigManager
import com.unifidokey.core.handler.SettingBasedUserVerificationHandler
import com.unifidokey.core.service.AuthenticatorService
import com.webauthn4j.ctap.authenticator.CachingUserVerificationHandler

class UnifidoKeyHandHeldApplication : UnifidoKeyApplicationBase<UnifidoKeyHandHeldComponent>() {

    companion object {

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
        authenticatorService.userVerificationHandler =
            CachingUserVerificationHandler(SettingBasedUserVerificationHandler(CtapAuthenticatorUserVerificationHandler(this, configManager, unifidoKeyComponent.relyingPartyDao), configManager))
        authenticatorService.credentialSelectionHandler = UnifidoKeyCredentialSelectionHandler(this)
    }
}
