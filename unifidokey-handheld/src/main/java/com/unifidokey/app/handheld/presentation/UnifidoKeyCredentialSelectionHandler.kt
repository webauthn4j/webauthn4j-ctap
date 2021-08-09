package com.unifidokey.app.handheld.presentation

import android.content.Context
import com.webauthn4j.ctap.authenticator.CredentialSelectionHandler
import com.webauthn4j.ctap.authenticator.store.UserCredential

class UnifidoKeyCredentialSelectionHandler(private val context: Context) :
    CredentialSelectionHandler {
    override suspend fun select(list: List<UserCredential>): UserCredential {
        return if (list.size == 1) {
            list.first()
        } else {
            val credentialSelectorDialogActivityStarter =
                CredentialSelectorDialogActivityStarter(context)
            val credentialViewModels = list.map {
                CredentialViewModel(
                    it.credentialId,
                    it.username,
                    it.displayName,
                    it.rpId,
                    it.rpName,
                    it.counter,
                    it.createdAt
                )
            }
            val request = CredentialSelectorDialogActivityRequest(credentialViewModels)
            credentialSelectorDialogActivityStarter
                .startForResult(request).let { response: CredentialSelectorDialogActivityResponse ->
                    list.first { item: UserCredential ->
                        item.credentialId.contentEquals(response.credential.id)
                    }
                }
        }
    }
}