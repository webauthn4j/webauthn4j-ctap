package com.webauthn4j.ctap.core.validator

import com.webauthn4j.ctap.core.data.AuthenticatorGetAssertionRequest
import com.webauthn4j.data.PinProtocolVersion

class AuthenticatorGetAssertionRequestValidator {

    fun validate(value: AuthenticatorGetAssertionRequest) {
        require(value.pinUvAuthParam == null || value.pinUvAuthParam?.size == 16) { "pinUvAuthParam must be 16 bytes length" }
        require(value.pinUvAuthProtocol == null || value.pinUvAuthProtocol == PinProtocolVersion.VERSION_1) { "Only PIN Protocol version 1 is supported" }
    }
}