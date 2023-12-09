package com.unifidokey.driver.credentials.provider

import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.lifecycleScope
import com.unifidokey.core.config.ConfigManager
import com.unifidokey.core.setting.UserConsentSetting
import com.webauthn4j.ctap.authenticator.MakeCredentialConsentRequest
import com.webauthn4j.ctap.authenticator.MakeCredentialConsentRequestHandler
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

class AndroidCredentialsMakeCredentialConsentRequestHandler(
    private val fragmentActivity: FragmentActivity,
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
            }
        }

        private suspend fun obtainMakeCredentialConsent(makeCredentialConsentRequest: MakeCredentialConsentRequest): Boolean {
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
                val promptInfo = BiometricPrompt.PromptInfo.Builder()
                    .setTitle("Authenticate to continue")
                    .setSubtitle(subtitle)
                    .setNegativeButtonText("Cancel")
                    .build()
                biometricPrompt.authenticate(promptInfo)
            }
            return deferred.await()
        }
}