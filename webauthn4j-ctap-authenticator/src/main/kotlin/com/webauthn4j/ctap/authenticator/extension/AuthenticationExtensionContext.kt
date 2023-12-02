package com.webauthn4j.ctap.authenticator.extension

import com.webauthn4j.ctap.authenticator.Connection
import com.webauthn4j.ctap.authenticator.data.credential.Credential
import com.webauthn4j.ctap.core.data.AuthenticatorGetAssertionRequest

data class AuthenticationExtensionContext(
    val connection: Connection,
    val getAssertionRequest: AuthenticatorGetAssertionRequest,
    val credential: Credential,
    val userVerificationPlan: Boolean,
    val userPresencePlan: Boolean
)