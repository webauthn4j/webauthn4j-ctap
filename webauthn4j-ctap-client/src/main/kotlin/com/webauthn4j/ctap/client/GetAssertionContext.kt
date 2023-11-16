package com.webauthn4j.ctap.client

class GetAssertionContext(
    val clientPINUserVerificationHandler: ClientPINUserVerificationHandler,
    val authenticatorUserVerificationHandler: AuthenticatorUserVerificationHandler = DefaultAuthenticatorUserVerificationHandler()) {

    private class DefaultAuthenticatorUserVerificationHandler: AuthenticatorUserVerificationHandler{
        override suspend fun onAuthenticatorUserVerificationStarted() {
            //nop
        }

        override suspend fun onAuthenticatorUserVerificationFinished() {
            //nop
        }

    }
}