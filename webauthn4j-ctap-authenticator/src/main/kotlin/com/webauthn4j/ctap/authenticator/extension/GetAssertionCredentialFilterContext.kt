package com.webauthn4j.ctap.authenticator.extension

import com.webauthn4j.ctap.authenticator.data.credential.Credential
import com.webauthn4j.ctap.core.data.AuthenticatorGetAssertionRequest

data class GetAssertionCredentialFilterContext(
    val request: AuthenticatorGetAssertionRequest,
    val credential: Credential,
    val uvResult: Boolean
)
