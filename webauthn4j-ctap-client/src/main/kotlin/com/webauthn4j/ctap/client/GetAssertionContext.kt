package com.webauthn4j.ctap.client

class GetAssertionContext(
    val clientPINUserVerificationHandler: ClientPINUserVerificationHandler,
    val authenticatorUserVerificationHandler: AuthenticatorUserVerificationHandler = NoopAuthenticatorUserVerificationHandler()
)
