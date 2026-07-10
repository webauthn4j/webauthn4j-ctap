package com.webauthn4j.ctap.authenticator.extension

import com.webauthn4j.ctap.authenticator.data.credential.Credential
import com.webauthn4j.ctap.core.data.AuthenticatorMakeCredentialRequest

data class MakeCredentialCredentialFilterContext(
    val request: AuthenticatorMakeCredentialRequest,
    val credential: Credential,
    val uvResult: Boolean
)
