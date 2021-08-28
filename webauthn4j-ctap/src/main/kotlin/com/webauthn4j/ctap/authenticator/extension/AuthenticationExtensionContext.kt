package com.webauthn4j.ctap.authenticator.extension

import com.webauthn4j.ctap.authenticator.CtapAuthenticator
import com.webauthn4j.ctap.authenticator.store.Credential
import com.webauthn4j.ctap.core.data.AuthenticatorGetAssertionRequest

data class AuthenticationExtensionContext(
    val ctapAuthenticator: CtapAuthenticator,
    val getAssertionRequest: AuthenticatorGetAssertionRequest,
    val credential: Credential,
    val userVerificationPlan: Boolean,
    val userPresencePlan: Boolean
)