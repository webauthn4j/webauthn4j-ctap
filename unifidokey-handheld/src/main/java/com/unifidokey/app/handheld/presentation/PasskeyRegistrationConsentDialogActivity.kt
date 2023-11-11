package com.unifidokey.app.handheld.presentation

import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import androidx.databinding.DataBindingUtil
import androidx.lifecycle.ViewModelProvider
import com.unifidokey.R
import com.unifidokey.databinding.PasskeyRegistrationConsentDialogActivityBinding
import com.unifidokey.driver.provider.PasskeyIntentProcessor
import kotlinx.coroutines.Dispatchers
import org.slf4j.LoggerFactory

/**
 * An example full-screen activity that shows and hides the system UI (i.e.
 * status bar and navigation/system bar) with user interaction.
 */
class PasskeyRegistrationConsentDialogActivity : AppCompatActivity(){

    private val logger = LoggerFactory.getLogger(PasskeyRegistrationConsentDialogActivity::class.java)

    //    private lateinit var biometricPrompt: BiometricPrompt
    private lateinit var viewModel: PasskeyRegistrationConsentDialogViewModel

    //region## Lifecycle event handlers ##
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.registration_consent_dialog_activity)
        setShowWhenLocked(true)
        val binding: PasskeyRegistrationConsentDialogActivityBinding =
            DataBindingUtil.setContentView(this, R.layout.passkey_registration_consent_dialog_activity)
//        biometricPrompt = BiometricPrompt(this, this.mainExecutor, AuthenticationCallback())
        viewModel = ViewModelProvider(this).get(PasskeyRegistrationConsentDialogViewModel::class.java)
        val intent = intent
//        @Suppress("DEPRECATION")
//        val request =
//            intent.getSerializableExtra(EXTRA_REQUEST) as RegistrationConsentDialogActivityRequest
//        viewModel.request = request
        binding.viewModel = viewModel
        binding.activity = this
        hideActionBar()

        viewModel.processIntent(this, intent)
    }



//    override fun onResume() {
//        super.onResume()
//        WakeLockUtil.acquireWakeLock(this)
//        KeepScreenOnUtil.configureKeepScreenOnFlag(this)
//    }
//
//    //endregion
//
//    @UiThread
//    @Suppress("UNUSED_PARAMETER")
//    fun onProceedButtonClick(view: View) {
//        viewModel.onProceed()
//    }
//
    private fun hideActionBar() {
        // Hide UI first
        val actionBar = supportActionBar
        actionBar?.hide()
    }
//
//    private fun sendResponseIntent(userConsent: Boolean) {
//        val intent = Intent()
//        val response = RegistrationConsentDialogActivityResponse(userConsent)
//        intent.putExtra(EXTRA_RESPONSE, response)
//        intent.action = ACTION_OPEN
//        val localBroadcastManager = LocalBroadcastManager.getInstance(applicationContext)
//        localBroadcastManager.sendBroadcast(intent)
//    }
//
//    @UiThread
//    override fun onBiometricPromptRequested(
//        onSuccessHandler: RegistrationConsentDialogViewModel.Callbacks.OnSuccessHandler?,
//        onFailureHandler: RegistrationConsentDialogViewModel.Callbacks.OnFailureHandler?
//    ) {
//        val subtitle = when (val rp = viewModel.request.rp){
//            null -> "Legacy Service(U2F) requires user verification."
//            else -> String.format("Service %s (%s) requires user verification.", rp.name, rp.id)
//        }
//        val promptInfo = PromptInfo.Builder()
//            .setTitle("Authenticate to continue")
//            .setSubtitle(subtitle)
//            .setNegativeButtonText("Cancel")
//            .build()
//        biometricPrompt.authenticate(promptInfo)
//    }
//
//    @UiThread
//    override fun onFinish(result: Boolean) {
//        val intent = Intent()
//        val response = RegistrationConsentDialogActivityResponse(result)
//        intent.putExtra(EXTRA_RESPONSE, response)
//        intent.action = ACTION_OPEN
//        val localBroadcastManager = LocalBroadcastManager.getInstance(applicationContext)
//        localBroadcastManager.sendBroadcast(intent)
//        finish()
//    }
//
//    private inner class AuthenticationCallback : BiometricPrompt.AuthenticationCallback() {
//        override fun onAuthenticationError(
//            errorCode: Int,
//            errString: CharSequence
//        ) {
//            when (errorCode) {
//                ERROR_HW_UNAVAILABLE, ERROR_UNABLE_TO_PROCESS, ERROR_TIMEOUT, ERROR_NO_SPACE, ERROR_CANCELED, ERROR_LOCKOUT, ERROR_VENDOR, ERROR_LOCKOUT_PERMANENT, ERROR_USER_CANCELED, ERROR_NO_BIOMETRICS, ERROR_HW_NOT_PRESENT, ERROR_NEGATIVE_BUTTON, ERROR_NO_DEVICE_CREDENTIAL -> {
//                    sendResponseIntent(false)
//                    finish()
//                }
//                else -> {
//                    sendResponseIntent(false)
//                    finish()
//                }
//            }
//        }
//
//        override fun onAuthenticationSucceeded(result: AuthenticationResult) {
//            sendResponseIntent(true)
//            finish()
//        }
//
//        override fun onAuthenticationFailed() {
//            sendResponseIntent(false)
//            finish()
//        }
//    }

    companion object {
        const val ACTION_OPEN =
            "com.unifidokey.app.handheld.presentation.RegistrationConsentDialogActivity.action.open"
        const val EXTRA_REQUEST =
            "com.unifidokey.app.handheld.presentation.RegistrationConsentDialogActivity.extra.request"
        const val EXTRA_RESPONSE =
            "com.unifidokey.app.handheld.presentation.RegistrationConsentDialogActivity.extra.response"
    }
}