package com.webauthn4j.ctap.core.validator

import com.webauthn4j.ctap.core.data.AuthenticatorMakeCredentialRequest
import com.webauthn4j.data.PinProtocolVersion

class AuthenticatorMakeCredentialRequestValidator {

    fun validate(value: AuthenticatorMakeCredentialRequest) {
        require(value.pinUvAuthParam == null || value.pinUvAuthParam?.isEmpty() == true || value.pinUvAuthParam?.size == 16) { "pinUvAuthParam must be empty or 16 bytes length" }
        require(value.pinUvAuthProtocol == null || value.pinUvAuthProtocol == PinProtocolVersion.VERSION_1) { "Only PIN Protocol version 1 is supported" }
    }
}