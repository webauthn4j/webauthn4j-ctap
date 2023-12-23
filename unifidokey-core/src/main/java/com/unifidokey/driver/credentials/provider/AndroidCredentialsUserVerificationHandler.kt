package com.unifidokey.driver.credentials.provider

import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
import androidx.biometric.BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED
import androidx.biometric.BiometricManager.BIOMETRIC_SUCCESS
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.lifecycleScope
import com.unifidokey.core.config.ConfigManager
import com.unifidokey.core.setting.BiometricAuthenticationSetting
import com.unifidokey.driver.persistence.dao.RelyingPartyDao
import com.webauthn4j.ctap.authenticator.GetAssertionConsentRequest
import com.webauthn4j.ctap.authenticator.MakeCredentialConsentRequest
import com.webauthn4j.ctap.authenticator.UserVerificationHandler
import com.webauthn4j.ctap.authenticator.data.settings.UserVerificationSetting
import com.webauthn4j.ctap.core.data.options.UserVerificationOption
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

class AndroidCredentialsUserVerificationHandler(
    private val fragmentActivity: FragmentActivity,
    private val configManager: ConfigManager,
    private val relyingPartyDao: RelyingPartyDao
) : UserVerificationHandler {

    private fun getAllowedUserVerificationMethods(rpId: String?): Int {
        rpId?.let {
            if(relyingPartyDao.findOne(rpId)?.relyingPartyEntity?.biometricAuthentication == false){
                return DEVICE_CREDENTIAL
            }
        }
        return when (configManager.biometricAuthentication.value) {
            BiometricAuthenticationSetting.ENABLED -> BIOMETRIC_STRONG or DEVICE_CREDENTIAL
            else -> DEVICE_CREDENTIAL
        }
    }

    override fun getUserVerificationOption(rpId: String?): UserVerificationOption? {
        val userVerificationSetting = configManager.userVerification.value
        val userVerificationMethods = getAllowedUserVerificationMethods(rpId)
        return when (BiometricManager.from(fragmentActivity).canAuthenticate(userVerificationMethods)) {
            BIOMETRIC_SUCCESS -> when (userVerificationSetting) {
                UserVerificationSetting.READY -> UserVerificationOption.READY
                UserVerificationSetting.NOT_READY -> UserVerificationOption.NOT_READY
                else -> UserVerificationOption.NOT_SUPPORTED
            }

            BIOMETRIC_ERROR_NONE_ENROLLED -> when (userVerificationSetting) {
                UserVerificationSetting.READY -> UserVerificationOption.NOT_READY
                UserVerificationSetting.NOT_READY -> UserVerificationOption.NOT_READY
                else -> UserVerificationOption.NOT_SUPPORTED
            }

            else -> UserVerificationOption.NOT_SUPPORTED
        }
    }

    override suspend fun onMakeCredentialConsentRequested(makeCredentialConsentRequest: MakeCredentialConsentRequest): Boolean {
        if(!makeCredentialConsentRequest.isUserVerificationRequired){
            return true //Skip biometric prompt because UP is already ensured by caller(Android Credentials Manager)
        }

        val deferred = CompletableDeferred<Boolean>()
        fragmentActivity.lifecycleScope.launch(Dispatchers.Main) {
            val biometricPrompt = BiometricPrompt(fragmentActivity, fragmentActivity.mainExecutor, object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    super.onAuthenticationError(errorCode, errString)
                    deferred.complete(false)
                }

                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    deferred.complete(true)
                }

                override fun onAuthenticationFailed() {
                    deferred.complete(false)
                }
            })
            val subtitle = String.format("Service %s (%s) requires user verification.", makeCredentialConsentRequest.rp!!.name, makeCredentialConsentRequest.rp!!.id)
            val userVerificationMethods = getAllowedUserVerificationMethods(makeCredentialConsentRequest.rp?.id)
            val promptInfo = BiometricPrompt.PromptInfo.Builder()
                .setTitle("Authenticate to continue")
                .setSubtitle(subtitle)
                .setAllowedAuthenticators(userVerificationMethods)
                .build()
            biometricPrompt.authenticate(promptInfo)
        }
        return deferred.await()
    }

    override suspend fun onGetAssertionConsentRequested(getAssertionConsentRequest: GetAssertionConsentRequest): Boolean {
        if(!getAssertionConsentRequest.isUserVerificationRequired){
            return true //Skip biometric prompt because UP is already ensured by caller(Android Credentials Manager)
        }

        val deferred = CompletableDeferred<Boolean>()
        fragmentActivity.lifecycleScope.launch(Dispatchers.Main) {
            val biometricPrompt = BiometricPrompt(fragmentActivity, fragmentActivity.mainExecutor, object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    super.onAuthenticationError(errorCode, errString)
                    deferred.complete(false)
                }

                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    deferred.complete(true)
                }

                override fun onAuthenticationFailed() {
                    deferred.complete(false)
                }
            })
            val userVerificationMethods = getAllowedUserVerificationMethods(getAssertionConsentRequest.rpId)
            val promptInfo = BiometricPrompt.PromptInfo.Builder()
                .setTitle("Authenticate to continue")
                .setSubtitle(
                    String.format(
                        "Service %s requires user verification.",
                        getAssertionConsentRequest.rpId
                    )
                )
                .setAllowedAuthenticators(userVerificationMethods)
                .build()
            biometricPrompt.authenticate(promptInfo)
        }
        return deferred.await()
    }
}