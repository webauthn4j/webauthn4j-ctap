package com.webauthn4j.ctap.core.validator

import com.webauthn4j.ctap.core.data.AuthenticatorGetAssertionRequest
import com.webauthn4j.ctap.core.data.PinProtocolVersion

class AuthenticatorGetAssertionRequestValidator {

    fun validate(value: AuthenticatorGetAssertionRequest){
        require(value.pinAuth == null || value.pinAuth?.size == 16){ "pinAuth must be 16 bytes length" }
        require(value.pinProtocol == null || value.pinProtocol == PinProtocolVersion.VERSION_1){ "Only PIN Protocol version 1 is supported" }
    }
}