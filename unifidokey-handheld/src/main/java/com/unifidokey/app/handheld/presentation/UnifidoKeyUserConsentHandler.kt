package com.unifidokey.app.handheld.presentation

import android.content.Context
import com.unifidokey.core.config.ConfigManager
import com.unifidokey.core.setting.UserConsentSetting
import com.webauthn4j.ctap.authenticator.GetAssertionConsentOptions
import com.webauthn4j.ctap.authenticator.MakeCredentialConsentOptions
import com.webauthn4j.ctap.authenticator.UserConsentHandler

class UnifidoKeyUserConsentHandler(
    private val context: Context,
    private val configManager: ConfigManager
) : UserConsentHandler {

    override suspend fun consentMakeCredential(options: MakeCredentialConsentOptions): Boolean {
        return when (configManager.userConsent.value) {
            UserConsentSetting.PROMPT_ANYTIME -> obtainMakeCredentialConsent(options)
            UserConsentSetting.IF_REQUIRED -> if (options.isUserPresence || options.isUserVerification) {
                obtainMakeCredentialConsent(options)
            } else {
                true
            }
            UserConsentSetting.CONSENT_AUTOMATICALLY -> true
            else -> throw IllegalStateException()
        }
    }

    override suspend fun consentGetAssertion(options: GetAssertionConsentOptions): Boolean {
        return when (configManager.userConsent.value) {
            UserConsentSetting.PROMPT_ANYTIME -> obtainGetAssertionConsent(options)
            UserConsentSetting.IF_REQUIRED -> if (options.isUserPresence || options.isUserVerification) {
                obtainGetAssertionConsent(options)
            } else {
                true
            }
            UserConsentSetting.CONSENT_AUTOMATICALLY -> true
            else -> throw IllegalStateException()
        }
    }

    private suspend fun obtainMakeCredentialConsent(options: MakeCredentialConsentOptions): Boolean {
        val registrationConsentDialogActivityStarter =
            RegistrationConsentDialogActivityStarter(context)
        val request = RegistrationConsentDialogActivityRequest(
            options.user,
            options.rp,
            options.isUserPresence,
            options.isUserVerification
        )
        return registrationConsentDialogActivityStarter.startForResult(request).isUserConsent
    }

    private suspend fun obtainGetAssertionConsent(options: GetAssertionConsentOptions): Boolean {
        val authenticationConsentDialogActivityStarter =
            AuthenticationConsentDialogActivityStarter(context)
        val request = AuthenticationConsentDialogActivityRequest(
            options.rpId,
            options.isUserPresence,
            options.isUserVerification
        )
        return authenticationConsentDialogActivityStarter.startForResult(request).isUserConsent
    }
}