package com.unifidokey.app.handheld.presentation

import android.content.Intent
import android.os.Bundle
import android.view.View
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.biometric.BiometricPrompt.PromptInfo
import androidx.databinding.DataBindingUtil
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.lifecycleScope
import com.google.android.material.button.MaterialButton
import com.unifidokey.R
import com.unifidokey.app.handheld.UnifidoKeyHandHeldApplication
import com.unifidokey.core.config.ConfigManager
import com.unifidokey.core.setting.BiometricAuthenticationSetting
import com.unifidokey.databinding.LockScreenActivityBinding
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

class LockScreenActivity : AppCompatActivity() {
    private lateinit var viewModel: LockScreenViewModel
    lateinit var lockScreenAuthenticationManager: LockScreenAuthenticationManager

    //region## Lifecycle event handlers ##
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.lock_screen_activity)
        val binding: LockScreenActivityBinding = DataBindingUtil.setContentView(this, R.layout.lock_screen_activity)
        viewModel = ViewModelProvider(this)[LockScreenViewModel::class.java]
        val unifidoKeyHandHeldApplication = application as UnifidoKeyHandHeldApplication
        val unifidoKeyComponent = unifidoKeyHandHeldApplication.unifidoKeyComponent
        lockScreenAuthenticationManager = LockScreenAuthenticationManager(unifidoKeyComponent.configManager)

        binding.viewModel = viewModel
        binding.activity = this
        hideActionBar()
    }

    override fun onResume() {
        super.onResume()
        if (!lockScreenAuthenticationManager.isPromptShownBefore) {
            lockScreenAuthenticationManager.tryUnlockApp()
        }
    }
    //endregion

    @Suppress("UNUSED_PARAMETER")
    fun onUnlockButtonClick(view: View) {
        lockScreenAuthenticationManager.tryUnlockApp()
    }

    private fun hideActionBar() {
        // Hide UI first
        val actionBar = supportActionBar
        actionBar?.hide()
    }

    inner class LockScreenAuthenticationManager(private val configManager: ConfigManager) {

        private val allowedAuthenticators: Int
            get() {
                return when (configManager.biometricAuthentication.value) {
                    BiometricAuthenticationSetting.ENABLED -> BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL
                    else -> BiometricManager.Authenticators.DEVICE_CREDENTIAL
                }
            }

        var isPromptShownBefore = false
            private set
        fun tryUnlockApp(){
            this@LockScreenActivity.lifecycleScope.launch {
                if(authenticate(this@LockScreenActivity)){
                    val intent = Intent(this@LockScreenActivity, MainActivity::class.java)
                    startActivity(intent)
                    finish()
                }
                else{
                    findViewById<MaterialButton>(R.id.unlockButton).visibility = View.VISIBLE
                    isPromptShownBefore = true
                }
            }
        }

        private suspend fun authenticate(fragmentActivity: FragmentActivity): Boolean{
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
                val builder = PromptInfo.Builder()
                    .setTitle("Authenticate to continue")
                    .setSubtitle(String.format("UnifidoKey requires user verification."))
                    .setAllowedAuthenticators(allowedAuthenticators)
                val promptInfo = builder.build()
                biometricPrompt.authenticate(promptInfo)
            }
            return deferred.await()
        }
    }

}