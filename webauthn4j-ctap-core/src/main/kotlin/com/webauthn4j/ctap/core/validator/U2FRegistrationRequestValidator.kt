package com.webauthn4j.ctap.core.validator

import com.webauthn4j.ctap.core.data.U2FRegistrationRequest

class U2FRegistrationRequestValidator {

    fun validate(value: U2FRegistrationRequest) {
        require(value.challengeParameter.size == 32) { "challengeParameter must be 32 bytes length" }
        require(value.applicationParameter.size == 32) { "applicationParameter must be 32 bytes length" }
    }
}