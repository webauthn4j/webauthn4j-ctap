package com.webauthn4j.ctap.core.validator

import com.webauthn4j.ctap.core.data.AuthenticatorMakeCredentialRequest
import com.webauthn4j.ctap.core.data.PinProtocolVersion

class AuthenticatorMakeCredentialRequestValidator {

    fun validate(value: AuthenticatorMakeCredentialRequest) {
        require(value.pinAuth == null || value.pinAuth?.isEmpty() == true || value.pinAuth?.size == 16) { "pinAuth must be empty or 16 bytes length" }
        require(value.pinProtocol == null || value.pinProtocol == PinProtocolVersion.VERSION_1) { "Only PIN Protocol version 1 is supported" }
    }
}