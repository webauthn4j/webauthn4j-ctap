package com.webauthn4j.ctap.authenticator

interface SelectionHandler {
    suspend fun onSelectionRequested(): Boolean
}
