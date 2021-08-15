package com.webauthn4j.ctap.authenticator

import com.webauthn4j.ctap.authenticator.store.Credential
import com.webauthn4j.ctap.authenticator.store.UserCredential
import java.io.Serializable

interface CredentialSelectionHandler {
    suspend fun select(list: List<Credential>): Credential
}
