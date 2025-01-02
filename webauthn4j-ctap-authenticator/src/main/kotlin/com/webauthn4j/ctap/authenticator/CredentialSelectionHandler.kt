package com.webauthn4j.ctap.authenticator

import com.webauthn4j.ctap.authenticator.data.credential.Credential

/**
 * Credential selection handler
 */
fun interface CredentialSelectionHandler {
    suspend fun onSelect(list: List<Credential>): Credential
}
