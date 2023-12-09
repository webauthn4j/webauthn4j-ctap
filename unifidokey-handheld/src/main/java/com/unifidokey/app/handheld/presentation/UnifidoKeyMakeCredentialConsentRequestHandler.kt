package com.unifidokey.app.handheld.presentation

import android.content.Context
import com.unifidokey.core.config.ConfigManager
import com.unifidokey.core.setting.UserConsentSetting
import com.webauthn4j.ctap.authenticator.MakeCredentialConsentRequest
import com.webauthn4j.ctap.authenticator.MakeCredentialConsentRequestHandler

class UnifidoKeyMakeCredentialConsentRequestHandler(
    private val context: Context,
    private val configManager: ConfigManager
) : MakeCredentialConsentRequestHandler {

    override suspend fun onMakeCredentialConsentRequested(makeCredentialConsentRequest: MakeCredentialConsentRequest): Boolean {
        return when (configManager.userConsent.value) {
            UserConsentSetting.PROMPT_ANYTIME -> obtainMakeCredentialConsent(makeCredentialConsentRequest)
            UserConsentSetting.IF_REQUIRED -> if (makeCredentialConsentRequest.isUserPresenceRequired || makeCredentialConsentRequest.isUserVerificationRequired) {
                obtainMakeCredentialConsent(makeCredentialConsentRequest)
            } else {
                true
            }
            UserConsentSetting.CONSENT_AUTOMATICALLY -> true
            else -> throw IllegalStateException()
        }
    }

    private suspend fun obtainMakeCredentialConsent(makeCredentialConsentRequest: MakeCredentialConsentRequest): Boolean {
        val registrationConsentDialogActivityStarter =
            RegistrationConsentDialogActivityStarter(context)
        val registrationConsentDialogActivityRequest = RegistrationConsentDialogActivityRequest(
            makeCredentialConsentRequest.user,
            makeCredentialConsentRequest.rp,
            makeCredentialConsentRequest.isUserPresenceRequired,
            makeCredentialConsentRequest.isUserVerificationRequired
        )
        return registrationConsentDialogActivityStarter.startForResult(registrationConsentDialogActivityRequest).consentResult
    }

}