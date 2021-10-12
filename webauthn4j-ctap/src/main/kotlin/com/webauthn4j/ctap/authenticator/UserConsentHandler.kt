package com.webauthn4j.ctap.authenticator

/**
 * User consent handler
 */
interface UserConsentHandler {

    /**
     * Process makeCredential consent request
     */
    suspend fun consentMakeCredential(options: MakeCredentialConsentOptions): Boolean

    /**
     * Process getAssertion consent request
     */
    suspend fun consentGetAssertion(options: GetAssertionConsentOptions): Boolean
}
