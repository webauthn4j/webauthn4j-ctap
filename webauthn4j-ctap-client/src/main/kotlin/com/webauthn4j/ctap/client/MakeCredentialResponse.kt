package com.webauthn4j.ctap.client

import com.webauthn4j.ctap.core.data.AuthenticatorGetInfoResponseData
import com.webauthn4j.data.attestation.AttestationObject
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData
import com.webauthn4j.data.attestation.statement.AttestationStatement
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorOutput

data class MakeCredentialResponse(
    val getInfoResponseData: AuthenticatorGetInfoResponseData,
    val authenticatorData: AuthenticatorData<RegistrationExtensionAuthenticatorOutput>,
    val attestationStatement: AttestationStatement
) {

    val attestationObject: AttestationObject
        get() = AttestationObject(authenticatorData, attestationStatement)
}
