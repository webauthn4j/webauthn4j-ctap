package com.unifidokey.driver.credentials.provider

import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.lifecycleScope
import com.unifidokey.core.config.ConfigManager
import com.unifidokey.core.setting.UserConsentSetting
import com.webauthn4j.ctap.authenticator.GetAssertionConsentRequest
import com.webauthn4j.ctap.authenticator.GetAssertionConsentRequestHandler
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

class AndroidCredentialsGetAssertionConsentRequestHandler(
    private val fragmentActivity: FragmentActivity,
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
        }
    }

    private suspend fun obtainGetAssertionConsent(getAssertionConsentRequest: GetAssertionConsentRequest): Boolean {
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
            val promptInfo = BiometricPrompt.PromptInfo.Builder()
                .setTitle("Authenticate to continue")
                .setSubtitle(
                    String.format(
                        "Service %s requires user verification.",
                        getAssertionConsentRequest.rpId
                    )
                )
                .setNegativeButtonText("Cancel")
                .build()
            biometricPrompt.authenticate(promptInfo)
        }
        return deferred.await()
    }
}