package com.webauthn4j.ctap.client

class MakeCredentialContext(
    val clientPINRequestHandler: ClientPINRequestHandler,
    val authenticatorUserVerificationHandler: AuthenticatorUserVerificationHandler = NoopAuthenticatorUserVerificationHandler())
