package com.webauthn4j.ctap.authenticator.extension

import com.webauthn4j.ctap.authenticator.CtapAuthenticator
import com.webauthn4j.ctap.core.data.AuthenticatorMakeCredentialRequest

class RegistrationExtensionContext(
    val ctapAuthenticator: CtapAuthenticator,
    val makeCredentialRequest: AuthenticatorMakeCredentialRequest)
