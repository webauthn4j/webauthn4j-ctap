package com.webauthn4j.ctap.authenticator

interface GetAssertionConsentHandler {
    suspend fun onGetAssertionConsentRequested(getAssertionConsentRequest: GetAssertionConsentRequest): Boolean
}
