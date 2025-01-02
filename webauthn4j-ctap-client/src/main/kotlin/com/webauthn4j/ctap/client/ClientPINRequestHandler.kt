package com.webauthn4j.ctap.client

import com.webauthn4j.ctap.authenticator.ClientPINUserVerificationCanceledException

fun interface ClientPINRequestHandler {

    @Throws(ClientPINUserVerificationCanceledException::class)
    suspend fun onClientPINRequested(): ByteArray
}
