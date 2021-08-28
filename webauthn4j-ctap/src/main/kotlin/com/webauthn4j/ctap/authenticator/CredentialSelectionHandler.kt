package com.webauthn4j.ctap.authenticator

import com.webauthn4j.ctap.authenticator.store.Credential

interface CredentialSelectionHandler {
    suspend fun select(list: List<Credential>): Credential
}
