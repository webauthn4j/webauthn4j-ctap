package com.unifidokey.app.handheld.presentation

import android.content.Context
import com.unifidokey.core.config.ConfigManager
import com.unifidokey.core.setting.UserConsentSetting
import com.webauthn4j.ctap.authenticator.GetAssertionConsentRequest
import com.webauthn4j.ctap.authenticator.GetAssertionConsentRequestHandler

class UnifidoKeyGetAssertionConsentRequestHandler(
    private val context: Context,
    private val configManager: ConfigManager
) : GetAssertionConsentRequestHandler {

    override suspend fun onGetAssertionConsentRequested(getAssertionConsentRequest: GetAssertionConsentRequest): Boolean {
        return when (configManager.userConsent.value) {
            UserConsentSetting.PROMPT_ANYTIME -> obtainGetAssertionConsent(getAssertionConsentRequest)
            UserConsentSetting.IF_REQUIRED -> if (getAssertionConsentRequest.isUserPresenceRequired || getAssertionConsentRequest.isUserVerificationRequired) {
                obtainGetAssertionConsent(getAssertionConsentRequest)
            } else {
                true
            }
            UserConsentSetting.CONSENT_AUTOMATICALLY -> true
            else -> throw IllegalStateException()
        }
    }

    private suspend fun obtainGetAssertionConsent(options: GetAssertionConsentRequest): Boolean {
        val authenticationConsentDialogActivityStarter =
            AuthenticationConsentDialogActivityStarter(context)
        val request = AuthenticationConsentDialogActivityRequest(
            options.rpId,
            options.isUserPresenceRequired,
            options.isUserVerificationRequired
        )
        return authenticationConsentDialogActivityStarter.startForResult(request).consentResult
    }
}
