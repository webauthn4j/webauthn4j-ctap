package com.unifidokey.app.handheld.presentation

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import com.unifidokey.R

class CredentialSelectorDialogViewModel(application: Application) : AndroidViewModel(application) {

    lateinit var credentials: List<CredentialViewModel>

    val description: String
        get() {
            val descCredentialSelectionRequest =
                getApplication<Application>().resources.getText(R.string.desc_credential_selection_request)
                    .toString()
            return String.format(descCredentialSelectionRequest, rpName)
        }

    val service: String?
        get() = rpId
    val rpId: String?
        get() = credentials.firstOrNull()?.rpId
    val rpName: String?
        get() = credentials.firstOrNull()?.rpName

    interface EventHandlers
}