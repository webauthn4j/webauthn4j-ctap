package com.webauthn4j.ctap.client

class GetAssertionContext(
    val clientPINRequestHandler: ClientPINRequestHandler,
    val authenticatorUserVerificationHandler: AuthenticatorUserVerificationHandler = NoopAuthenticatorUserVerificationHandler()
)
