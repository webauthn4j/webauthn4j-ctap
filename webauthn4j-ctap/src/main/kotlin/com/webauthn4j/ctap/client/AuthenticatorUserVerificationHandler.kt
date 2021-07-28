package com.webauthn4j.ctap.client

interface AuthenticatorUserVerificationHandler {
    suspend fun onAuthenticatorUserVerificationStarted()
    suspend fun onAuthenticatorUserVerificationFinished()
}