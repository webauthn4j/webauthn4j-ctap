package com.webauthn4j.ctap.authenticator

/**
 * Handler interface to process wink request
 */
fun interface WinkHandler {

    suspend fun onWink()
}
