package com.webauthn4j.ctap.authenticator

interface AuthenticatorSelectionHandler {
    suspend fun onSelectionRequested(): Boolean
}
