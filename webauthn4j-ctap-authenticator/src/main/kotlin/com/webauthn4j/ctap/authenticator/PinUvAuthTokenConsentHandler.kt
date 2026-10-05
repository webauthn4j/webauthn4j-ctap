package com.webauthn4j.ctap.authenticator

fun interface PinUvAuthTokenConsentHandler {
    suspend fun onPinUvAuthTokenConsentRequested(
        request: PinUvAuthTokenConsentRequest
    ): Boolean
}
