package com.unifidokey.app.handheld.presentation

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import com.unifidokey.R

class AuthenticationConsentDialogViewModel(application: Application) :
    AndroidViewModel(application) {
    lateinit var callbacks: Callbacks
    lateinit var request: AuthenticationConsentDialogActivityRequest
    val description: String
        get() = getApplication<Application>().resources.getText(R.string.desc_authentication_request)
            .toString()
    val service: String
        get() = request.rpId

    fun onProceed() {
        val callbacks = callbacks
        if (request.isUserVerification) {
            callbacks.onBiometricPromptRequested(
                { callbacks.onFinish(true) },
                { callbacks.onFinish(false) })
        } else {
            callbacks.onFinish(true)
        }
    }

    interface Callbacks {
        fun onBiometricPromptRequested(
            onSuccessHandler: OnSuccessHandler,
            onFailureHandler: OnFailureHandler
        )

        fun onFinish(result: Boolean)
        fun interface OnSuccessHandler {
            fun onSuccess()
        }

        fun interface OnFailureHandler {
            fun onFailure()
        }
    }
}