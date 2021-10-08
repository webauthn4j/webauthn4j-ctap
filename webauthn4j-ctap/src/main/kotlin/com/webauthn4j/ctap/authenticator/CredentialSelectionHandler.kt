package com.webauthn4j.ctap.authenticator

import com.webauthn4j.ctap.authenticator.data.credential.Credential

interface CredentialSelectionHandler {
    suspend fun select(list: List<Credential>): Credential
}
