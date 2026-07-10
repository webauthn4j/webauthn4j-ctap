package com.webauthn4j.ctap.core.validator

import com.webauthn4j.ctap.core.data.AuthenticatorGetAssertionRequest
import com.webauthn4j.data.PinProtocolVersion

class AuthenticatorGetAssertionRequestValidator {

    fun validate(value: AuthenticatorGetAssertionRequest) {
        require(value.pinUvAuthProtocol == null || value.pinUvAuthProtocol == PinProtocolVersion.VERSION_1 || value.pinUvAuthProtocol == PinProtocolVersion.VERSION_2) { "Unsupported PIN Protocol version" }
        validatePinUvAuthParamSize(value.pinUvAuthParam, value.pinUvAuthProtocol)
    }

    companion object {
        private fun validatePinUvAuthParamSize(pinUvAuthParam: ByteArray?, pinUvAuthProtocol: PinProtocolVersion?) {
            if (pinUvAuthParam == null || pinUvAuthParam.isEmpty()) return
            val expectedSize = when (pinUvAuthProtocol) {
                PinProtocolVersion.VERSION_1 -> 16
                PinProtocolVersion.VERSION_2 -> 32
                else -> return
            }
            require(pinUvAuthParam.size == expectedSize) { "pinUvAuthParam must be $expectedSize bytes for PIN Protocol ${pinUvAuthProtocol.value}" }
        }
    }
}
