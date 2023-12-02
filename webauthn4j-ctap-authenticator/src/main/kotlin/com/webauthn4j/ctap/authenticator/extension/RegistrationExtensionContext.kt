package com.webauthn4j.ctap.authenticator.extension

import com.webauthn4j.ctap.authenticator.Connection
import com.webauthn4j.ctap.core.data.AuthenticatorMakeCredentialRequest

class RegistrationExtensionContext(
    val connection: Connection,
    val makeCredentialRequest: AuthenticatorMakeCredentialRequest
)
