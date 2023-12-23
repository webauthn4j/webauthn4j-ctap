package com.unifidokey.app.handheld.presentation

import android.content.Context
import androidx.biometric.BiometricManager
import com.unifidokey.core.config.ConfigManager
import com.unifidokey.core.setting.BiometricAuthenticationSetting
import com.unifidokey.driver.persistence.dao.RelyingPartyDao
import com.webauthn4j.ctap.authenticator.GetAssertionConsentRequest
import com.webauthn4j.ctap.authenticator.MakeCredentialConsentRequest
import com.webauthn4j.ctap.authenticator.UserVerificationHandler
import com.webauthn4j.ctap.authenticator.data.settings.UserVerificationSetting
import com.webauthn4j.ctap.core.data.options.UserVerificationOption

class CtapAuthenticatorUserVerificationHandler(
    private val context: Context,
    private val configManager: ConfigManager,
    private val relyingPartyDao: RelyingPartyDao
) : UserVerificationHandler {

    private fun getAllowedAuthenticator(rpId: String?): Int {
        rpId?.let {
            if(relyingPartyDao.findOne(rpId)?.relyingPartyEntity?.biometricAuthentication == false){
                return BiometricManager.Authenticators.DEVICE_CREDENTIAL
            }
        }
        return when (configManager.biometricAuthentication.value) {
            BiometricAuthenticationSetting.ENABLED -> BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL
            else -> BiometricManager.Authenticators.DEVICE_CREDENTIAL
        }
    }

    override fun getUserVerificationOption(rpId: String?): UserVerificationOption? {
        val userVerificationSetting = configManager.userVerification.value
        return when (BiometricManager.from(context).canAuthenticate(getAllowedAuthenticator(rpId))) {
            BiometricManager.BIOMETRIC_SUCCESS -> when (userVerificationSetting) {
                UserVerificationSetting.READY -> UserVerificationOption.READY
                UserVerificationSetting.NOT_READY -> UserVerificationOption.NOT_READY
                else -> UserVerificationOption.NOT_SUPPORTED
            }

            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> when (userVerificationSetting) {
                UserVerificationSetting.READY -> UserVerificationOption.NOT_READY
                UserVerificationSetting.NOT_READY -> UserVerificationOption.NOT_READY
                else -> UserVerificationOption.NOT_SUPPORTED
            }

            else -> UserVerificationOption.NOT_SUPPORTED
        }
    }

    override suspend fun onMakeCredentialConsentRequested(makeCredentialConsentRequest: MakeCredentialConsentRequest): Boolean {
        val registrationConsentDialogActivityStarter =
            RegistrationConsentDialogActivityStarter(context)
        val registrationConsentDialogActivityRequest = RegistrationConsentDialogActivityRequest(
            makeCredentialConsentRequest.user,
            makeCredentialConsentRequest.rp,
            makeCredentialConsentRequest.isUserPresenceRequired,
            makeCredentialConsentRequest.isUserVerificationRequired,
            getAllowedAuthenticator(makeCredentialConsentRequest.rp?.id)
        )
        return registrationConsentDialogActivityStarter.startForResult(registrationConsentDialogActivityRequest).consentResult
    }

    override suspend fun onGetAssertionConsentRequested(getAssertionConsentRequest: GetAssertionConsentRequest): Boolean {
        val authenticationConsentDialogActivityStarter =
            AuthenticationConsentDialogActivityStarter(context)
        val request = AuthenticationConsentDialogActivityRequest(
            getAssertionConsentRequest.rpId,
            getAssertionConsentRequest.isUserPresenceRequired,
            getAssertionConsentRequest.isUserVerificationRequired,
            getAllowedAuthenticator(getAssertionConsentRequest.rpId)
        )
        return authenticationConsentDialogActivityStarter.startForResult(request).consentResult
    }
}