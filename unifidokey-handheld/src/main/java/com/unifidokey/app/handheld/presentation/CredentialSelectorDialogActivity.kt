package com.unifidokey.app.handheld.presentation

import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import com.unifidokey.R
import com.unifidokey.app.handheld.presentation.helper.KeepScreenOnHelper

class CredentialSelectorDialogActivity : AppCompatActivity() {
    //region## Lifecycle event handlers ##
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.credential_chooser_dialog_activity)
        setShowWhenLocked(true)
        if (savedInstanceState == null) {
            supportFragmentManager.beginTransaction()
                .replace(R.id.container, CredentialSelectorDialogFragment.newInstance())
                .commitNow()
        }
    }

    override fun onResume() {
        super.onResume()
        KeepScreenOnHelper.configureKeepScreenOnFlag(this)
    } //endregion

    companion object {
        const val ACTION_OPEN =
            "com.unifidokey.app.handheld.presentation.CredentialChooserDialogActivity.action.open"
        const val EXTRA_REQUEST =
            "com.unifidokey.app.handheld.presentation.CredentialChooserDialogActivity.extra.request"
        const val EXTRA_RESPONSE =
            "com.unifidokey.app.handheld.presentation.CredentialChooserDialogActivity.extra.response"
    }
}