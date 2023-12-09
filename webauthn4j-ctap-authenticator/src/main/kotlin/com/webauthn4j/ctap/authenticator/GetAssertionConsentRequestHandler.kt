package com.webauthn4j.ctap.authenticator

/**
 * User consent handler
 */
fun interface GetAssertionConsentRequestHandler {

    /**
     * Process getAssertion consent request
     */
    suspend fun onGetAssertionConsentRequested(getAssertionConsentRequest: GetAssertionConsentRequest): Boolean
}
