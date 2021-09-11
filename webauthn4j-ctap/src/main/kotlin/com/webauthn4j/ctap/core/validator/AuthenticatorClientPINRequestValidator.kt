package com.webauthn4j.ctap.core.validator

import com.webauthn4j.ctap.core.data.AuthenticatorClientPINRequest
import com.webauthn4j.ctap.core.data.PinProtocolVersion
import com.webauthn4j.ctap.core.data.PinSubCommand

class AuthenticatorClientPINRequestValidator {

    fun validate(value: AuthenticatorClientPINRequest){
        require(value.pinProtocol == PinProtocolVersion.VERSION_1){"Only PIN Protocol version 1 is supported"}
        when(value.subCommand){
            PinSubCommand.GET_PIN_RETRIES -> {
                // nop
            }
            PinSubCommand.GET_KEY_AGREEMENT -> {
                // nop
            }
            PinSubCommand.SET_PIN -> {
                requireNotNull(value.keyAgreement)
                requireNotNull(value.newPinEnc)
                val pinAuth = value.pinAuth
                requireNotNull(pinAuth)
                require(pinAuth.size == 16){ "pinAuth must be 16 bytes length" }
            }
            PinSubCommand.CHANGE_PIN -> {
                requireNotNull(value.keyAgreement)
                requireNotNull(value.pinHashEnc)
                requireNotNull(value.newPinEnc)
                val pinAuth = value.pinAuth
                requireNotNull(pinAuth)
                require(pinAuth.size == 16){ "pinAuth must be 16 bytes length" }
            }
            PinSubCommand.GET_PIN_TOKEN -> {
                requireNotNull(value.keyAgreement)
                requireNotNull(value.pinHashEnc)
            }
        }
    }
}