package com.webauthn4j.ctap.core.validator

import com.webauthn4j.ctap.core.data.U2FAuthenticationRequest

class U2FAuthenticationRequestValidator {

    fun validate(value: U2FAuthenticationRequest) {
        require(value.challengeParameter.size == 32) { "challengeParameter must be 32 bytes length" }
        require(value.applicationParameter.size == 32) { "applicationParameter must be 32 bytes length" }
    }
}