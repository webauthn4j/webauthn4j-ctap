package com.unifidokey.app.handheld.presentation

import android.content.Intent
import android.os.Bundle
import android.view.View
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricPrompt
import androidx.biometric.BiometricPrompt.*
import androidx.databinding.DataBindingUtil
import androidx.lifecycle.ViewModelProvider
import androidx.localbroadcastmanager.content.LocalBroadcastManager
import com.unifidokey.R
import com.unifidokey.app.handheld.presentation.helper.KeepScreenOnHelper
import com.unifidokey.databinding.AuthenticationConsentDialogActivityBinding

/**
 * An example full-screen activity that shows and hides the system UI (i.e.
 * status bar and navigation/system bar) with user interaction.
 */
class AuthenticationConsentDialogActivity : AppCompatActivity(),
    AuthenticationConsentDialogViewModel.Callbacks {
    private lateinit var viewModel: AuthenticationConsentDialogViewModel

    //region## Lifecycle event handlers ##
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.authentication_consent_dialog_activity)
        setShowWhenLocked(true)
        hideActionBar()
        val intent = intent
        val request =
            intent.getSerializableExtra(EXTRA_REQUEST) as AuthenticationConsentDialogActivityRequest
        val binding: AuthenticationConsentDialogActivityBinding =
            DataBindingUtil.setContentView(this, R.layout.authentication_consent_dialog_activity)
        viewModel = ViewModelProvider(this).get(AuthenticationConsentDialogViewModel::class.java)
        viewModel.request = request
        viewModel.callbacks = this
        binding.viewModel = viewModel
        binding.activity = this
    }

    override fun onResume() {
        super.onResume()
        KeepScreenOnHelper.configureKeepScreenOnFlag(this)
    }

    //endregion
    //region## User action event handlers ##
    @Suppress("UNUSED_PARAMETER")
    fun onProceedButtonClick(view: View) {
        viewModel.onProceed()
    }

    //endregion
    //region## callbacks
    override fun onBiometricPromptRequested(
        onSuccessHandler: AuthenticationConsentDialogViewModel.Callbacks.OnSuccessHandler,
        onFailureHandler: AuthenticationConsentDialogViewModel.Callbacks.OnFailureHandler
    ) {
        val promptInfo = PromptInfo.Builder()
            .setTitle("Authenticate to continue")
            .setSubtitle(
                String.format(
                    "Service %s requires user verification.",
                    viewModel.request.rpId
                )
            )
            .setNegativeButtonText("Cancel")
            .build()
        val biometricPrompt = BiometricPrompt(
            this,
            this.mainExecutor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: AuthenticationResult) {
                    super.onAuthenticationSucceeded(result)
                    onSuccessHandler.onSuccess()
                }

                override fun onAuthenticationFailed() {
                    super.onAuthenticationFailed()
                    onFailureHandler.onFailure()
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    super.onAuthenticationError(errorCode, errString)
                    when (errorCode) {
                        ERROR_HW_UNAVAILABLE, ERROR_UNABLE_TO_PROCESS, ERROR_TIMEOUT, ERROR_NO_SPACE, ERROR_CANCELED, ERROR_LOCKOUT, ERROR_VENDOR, ERROR_LOCKOUT_PERMANENT, ERROR_USER_CANCELED, ERROR_NO_BIOMETRICS, ERROR_HW_NOT_PRESENT, ERROR_NEGATIVE_BUTTON, ERROR_NO_DEVICE_CREDENTIAL -> onFailureHandler.onFailure()
                        else -> onFailureHandler.onFailure()
                    }
                }
            })
        biometricPrompt.authenticate(promptInfo)
    }

    override fun onFinish(result: Boolean) {
        val intent = Intent()
        val response = AuthenticationConsentDialogActivityResponse(result)
        intent.putExtra(EXTRA_RESPONSE, response)
        intent.action = ACTION_OPEN
        val localBroadcastManager = LocalBroadcastManager.getInstance(applicationContext)
        localBroadcastManager.sendBroadcast(intent)
        finish()
    }

    //endregion
    private fun hideActionBar() {
        // Hide UI first
        val actionBar = supportActionBar
        actionBar?.hide()
    }

    companion object {
        const val ACTION_OPEN =
            "com.unifidokey.app.handheld.presentation.AuthenticationConsentDialogActivity.action.open"
        const val EXTRA_REQUEST =
            "com.unifidokey.app.handheld.presentation.AuthenticationConsentDialogActivity.extra.request"
        const val EXTRA_RESPONSE =
            "com.unifidokey.app.handheld.presentation.AuthenticationConsentDialogActivity.extra.response"
    }
}