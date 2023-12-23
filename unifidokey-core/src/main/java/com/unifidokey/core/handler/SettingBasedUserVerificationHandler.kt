package com.unifidokey.core.handler

import com.unifidokey.core.config.ConfigManager
import com.unifidokey.core.setting.UserConsentSetting
import com.webauthn4j.ctap.authenticator.GetAssertionConsentRequest
import com.webauthn4j.ctap.authenticator.MakeCredentialConsentRequest
import com.webauthn4j.ctap.authenticator.UserVerificationHandler
import com.webauthn4j.ctap.core.data.options.UserVerificationOption

class SettingBasedUserVerificationHandler(private val userVerificationHandler: UserVerificationHandler, private val configManager: ConfigManager) : UserVerificationHandler {
    override fun getUserVerificationOption(rpId: String?): UserVerificationOption? =
        userVerificationHandler.getUserVerificationOption(rpId)

    override suspend fun onMakeCredentialConsentRequested(makeCredentialConsentRequest: MakeCredentialConsentRequest): Boolean {
        return when (configManager.userConsent.value) {
            UserConsentSetting.CONSENT_AUTOMATICALLY -> true
            UserConsentSetting.ASK_IF_REQUIRED -> when {
                makeCredentialConsentRequest.isUserPresenceRequired || makeCredentialConsentRequest.isUserVerificationRequired -> {
                    userVerificationHandler.onMakeCredentialConsentRequested(makeCredentialConsentRequest)
                }
                else -> true
            }
        }
    }

    override suspend fun onGetAssertionConsentRequested(getAssertionConsentRequest: GetAssertionConsentRequest): Boolean {
        return when (configManager.userConsent.value) {
            UserConsentSetting.CONSENT_AUTOMATICALLY -> true
            UserConsentSetting.ASK_IF_REQUIRED-> {
                when {
                    getAssertionConsentRequest.isUserPresenceRequired || getAssertionConsentRequest.isUserVerificationRequired -> {
                        userVerificationHandler.onGetAssertionConsentRequested(getAssertionConsentRequest)
                    }
                    else -> true
                }
            }
        }
    }
}
