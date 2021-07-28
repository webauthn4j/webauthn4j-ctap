package com.unifidokey.app.handheld.presentation

import android.app.Application
import android.view.View
import androidx.annotation.UiThread
import androidx.lifecycle.AndroidViewModel
import com.unifidokey.R

class RegistrationConsentDialogViewModel(application: Application) : AndroidViewModel(application) {

    lateinit var callbacks: Callbacks
    lateinit var request: RegistrationConsentDialogActivityRequest
    val service: String?
        get() = request.rp.id
    val username: String
        get() {
            return request.user.displayName
        }
    val description: String
        get() {
            val descRegistrationRequest =
                getApplication<Application>().resources.getText(R.string.desc_registration_request)
                    .toString()
            return String.format(descRegistrationRequest, request.rp.id)
        }

    @UiThread
    fun onProceed() {
        if (request.isUserVerification) {
            callbacks.onBiometricPromptRequested(
                { callbacks.onFinish(true) },
                { callbacks.onFinish(false) })
        } else {
            callbacks.onFinish(true)
        }
    }

    interface EventHandlers {
        fun onProceedButtonClick(view: View?)
    }

    interface Callbacks {
        fun onBiometricPromptRequested(
            onSuccessHandler: OnSuccessHandler?,
            onFailureHandler: OnFailureHandler?
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