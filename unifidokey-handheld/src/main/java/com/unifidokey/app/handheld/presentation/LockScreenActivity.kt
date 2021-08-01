package com.unifidokey.app.handheld.presentation

import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricPrompt
import androidx.biometric.BiometricPrompt.*
import androidx.databinding.DataBindingUtil
import androidx.lifecycle.ViewModelProvider
import com.unifidokey.R
import com.unifidokey.app.handheld.presentation.util.KeepScreenOnUtil
import com.unifidokey.databinding.LockScreenActivityBinding

/**
 * An example full-screen activity that shows and hides the system UI (i.e.
 * status bar and navigation/system bar) with user interaction.
 */
class LockScreenActivity : AppCompatActivity(), LockScreenViewModel.EventHandlers {
    private var biometricPrompt: BiometricPrompt? = null
    private var isPromptShownBefore = false
    private lateinit var request: RegistrationConsentDialogActivityRequest

    //region## Lifecycle event handlers ##
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.lock_screen_activity)
        val binding: LockScreenActivityBinding =
            DataBindingUtil.setContentView(this, R.layout.lock_screen_activity)
        val viewModel = ViewModelProvider(this).get(LockScreenViewModel::class.java)
        binding.viewModel = viewModel
        binding.handlers = this
        biometricPrompt = BiometricPrompt(this, this.mainExecutor, AuthenticationCallback())
        hideActionBar()
    }

    override fun onResume() {
        super.onResume()
        if (!isPromptShownBefore) {
            showBiometricPrompt()
        }
        KeepScreenOnUtil.configureKeepScreenOnFlag(this)
    }
    //endregion

    private fun hideActionBar() {
        // Hide UI first
        val actionBar = supportActionBar
        actionBar?.hide()
    }

    private fun showBiometricPrompt() {
        val serviceString = String.format("Service %s (%s)", request.rp.name, request.rp.id)
        val userString = String.format("User %s", request.user.displayName)
        val promptInfo = PromptInfo.Builder()
            .setTitle("Authenticate to continue")
            .setSubtitle(String.format("%s requires user verification.", serviceString))
            .setDescription(String.format("%s is your account", userString))
            .setNegativeButtonText("Cancel")
            .build()
        biometricPrompt!!.authenticate(promptInfo)
        isPromptShownBefore = true
    }

    private fun dismissLockScreen() {
        finish()
    }

    private inner class AuthenticationCallback : BiometricPrompt.AuthenticationCallback() {
        override fun onAuthenticationError(
            errorCode: Int,
            errString: CharSequence
        ) {
            when (errorCode) {
                ERROR_HW_UNAVAILABLE, ERROR_UNABLE_TO_PROCESS, ERROR_TIMEOUT, ERROR_NO_SPACE, ERROR_CANCELED, ERROR_LOCKOUT, ERROR_VENDOR, ERROR_LOCKOUT_PERMANENT, ERROR_USER_CANCELED, ERROR_NO_BIOMETRICS, ERROR_HW_NOT_PRESENT, ERROR_NEGATIVE_BUTTON, ERROR_NO_DEVICE_CREDENTIAL -> {
                    dismissLockScreen()
                    finish()
                }
                else -> {
                    dismissLockScreen()
                    finish()
                }
            }
        }

        override fun onAuthenticationSucceeded(result: AuthenticationResult) {
            dismissLockScreen()
            finish()
        }

        override fun onAuthenticationFailed() {
            dismissLockScreen()
            finish()
        }
    }
}