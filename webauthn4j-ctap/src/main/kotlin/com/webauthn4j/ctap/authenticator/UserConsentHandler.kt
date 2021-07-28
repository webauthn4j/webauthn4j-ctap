package com.webauthn4j.ctap.authenticator

interface UserConsentHandler {

    suspend fun consentMakeCredential(options: MakeCredentialConsentOptions): Boolean

    suspend fun consentGetAssertion(options: GetAssertionConsentOptions): Boolean
}