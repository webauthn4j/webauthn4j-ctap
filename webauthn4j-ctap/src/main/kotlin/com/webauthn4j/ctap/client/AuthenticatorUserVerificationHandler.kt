package com.webauthn4j.ctap.client

interface AuthenticatorUserVerificationHandler {
    //TODO: revisit interface design by implementing real application
    suspend fun onAuthenticatorUserVerificationStarted()
    suspend fun onAuthenticatorUserVerificationFinished()
}