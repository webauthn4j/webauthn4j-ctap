package com.unifidokey.app.handheld.presentation

import android.content.Context
import com.webauthn4j.ctap.authenticator.CredentialSelectionHandler
import com.webauthn4j.ctap.authenticator.data.credential.Credential
import com.webauthn4j.ctap.authenticator.data.credential.UserCredential

class UnifidoKeyCredentialSelectionHandler(private val context: Context) :
    CredentialSelectionHandler {
    override suspend fun onSelect(list: List<Credential>): Credential {
        return if (list.size == 1) {
            list.first()
        } else {
            val credentialSelectorDialogActivityStarter =
                CredentialSelectorDialogActivityStarter(context)
            val credentialViewModels = list.map {
                when(it){
                    is UserCredential -> CredentialViewModel(
                        it.credentialId,
                        it.username,
                        it.displayName,
                        it.rpId,
                        it.rpName,
                        it.counter,
                        it.createdAt
                    )
                    else -> CredentialViewModel(
                        it.credentialId,
                        null,
                        null,
                        null,
                        null,
                        it.counter,
                        it.createdAt
                    )
                }
            }
            val request = CredentialSelectorDialogActivityRequest(credentialViewModels)
            credentialSelectorDialogActivityStarter
                .startForResult(request).let { response: CredentialSelectorDialogActivityResponse ->
                    list.first { item ->
                        item.credentialId.contentEquals(response.credential.id)
                    }
                }
        }
    }
}