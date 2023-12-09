package com.webauthn4j.ctap.authenticator.extension

import com.webauthn4j.ctap.authenticator.CtapAuthenticatorSession
import com.webauthn4j.ctap.core.data.AuthenticatorMakeCredentialRequest

class RegistrationExtensionContext(
    val ctapAuthenticatorSession: CtapAuthenticatorSession,
    val makeCredentialRequest: AuthenticatorMakeCredentialRequest
)
