package com.unifidokey.app.handheld.presentation

import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import androidx.databinding.DataBindingUtil
import androidx.lifecycle.ViewModelProvider
import com.unifidokey.R
import com.unifidokey.databinding.AndroidCredentialsDialogActivityBinding
import org.slf4j.LoggerFactory

/**
 * An example full-screen activity that shows and hides the system UI (i.e.
 * status bar and navigation/system bar) with user interaction.
 */
class AndroidCredentialsDialogActivity : AppCompatActivity(){

    private val logger = LoggerFactory.getLogger(AndroidCredentialsDialogActivity::class.java)

    private lateinit var viewModel: AndroidCredentialsDialogViewModel

    //region## Lifecycle event handlers ##
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.registration_consent_dialog_activity)
        setShowWhenLocked(true)
        val binding: AndroidCredentialsDialogActivityBinding =
            DataBindingUtil.setContentView(this, R.layout.android_credentials_dialog_activity)
        viewModel = ViewModelProvider(this)[AndroidCredentialsDialogViewModel::class.java]
        val intent = intent
        binding.viewModel = viewModel
        binding.activity = this
        hideActionBar()

        viewModel.processIntent(this, intent)
    }
    private fun hideActionBar() {
        // Hide UI first
        val actionBar = supportActionBar
        actionBar?.hide()
    }


    companion object {
        const val ACTION_OPEN =
            "com.unifidokey.app.handheld.presentation.RegistrationConsentDialogActivity.action.open"
        const val EXTRA_REQUEST =
            "com.unifidokey.app.handheld.presentation.RegistrationConsentDialogActivity.extra.request"
        const val EXTRA_RESPONSE =
            "com.unifidokey.app.handheld.presentation.RegistrationConsentDialogActivity.extra.response"
    }
}