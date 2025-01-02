package com.webauthn4j.ctap.client

class NoopAuthenticatorUserVerificationHandler: AuthenticatorUserVerificationHandler {
    override suspend fun onAuthenticatorUserVerificationStarted() {
        //nop
    }

    override suspend fun onAuthenticatorUserVerificationFinished() {
        //nop
    }
}