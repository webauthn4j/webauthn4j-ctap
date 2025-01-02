package com.webauthn4j.ctap.authenticator.extension

import com.webauthn4j.ctap.authenticator.CtapAuthenticatorSession
import com.webauthn4j.ctap.authenticator.data.credential.Credential
import com.webauthn4j.ctap.core.data.AuthenticatorGetAssertionRequest

data class AuthenticationExtensionContext(
    val ctapAuthenticatorSession: CtapAuthenticatorSession,
    val getAssertionRequest: AuthenticatorGetAssertionRequest,
    val credential: Credential,
    val userVerificationPlan: Boolean,
    val userPresencePlan: Boolean
)