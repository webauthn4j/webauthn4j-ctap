package com.webauthn4j.ctap.client

class MakeCredentialContext(
    val clientPINUserVerificationHandler: ClientPINUserVerificationHandler,
    val authenticatorUserVerificationHandler: AuthenticatorUserVerificationHandler) {
}