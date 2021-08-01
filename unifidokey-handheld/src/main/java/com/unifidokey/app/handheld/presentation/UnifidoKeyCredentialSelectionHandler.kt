package com.unifidokey.app.handheld.presentation

import android.content.Context
import com.webauthn4j.ctap.authenticator.CredentialSelectionHandler
import com.webauthn4j.ctap.authenticator.store.UserCredential
import java.io.Serializable

class UnifidoKeyCredentialSelectionHandler(private val context: Context) :
    CredentialSelectionHandler {
    override suspend fun select(list: List<UserCredential<Serializable?>>): UserCredential<Serializable?> {
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
                    list.first { item: UserCredential<Serializable?> ->
                        item.credentialId.contentEquals(response.credential.id)
                    }
                }
        }
    }
}