package com.webauthn4j.ctap.authenticator

/**
 * Handler interface to process wink request
 */
interface WinkHandler {

    suspend fun wink()
}
