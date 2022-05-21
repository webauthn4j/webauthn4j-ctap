package com.webauthn4j.ctap.client

import com.webauthn4j.ctap.authenticator.exception.ClientPINUserVerificationCanceledException

interface ClientPINUserVerificationHandler {

    @Throws(ClientPINUserVerificationCanceledException::class)
    suspend fun onClientPINRequested(): String
}
