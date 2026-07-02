package com.webauthn4j.ctap.core.validator

import com.webauthn4j.ctap.core.data.AuthenticatorClientPINRequest
import com.webauthn4j.data.PinProtocolVersion
import com.webauthn4j.ctap.core.data.PinSubCommand

class AuthenticatorClientPINRequestValidator {

    fun validate(value: AuthenticatorClientPINRequest) {
        val pinProtocol = value.pinProtocol
        require(pinProtocol == PinProtocolVersion.VERSION_1 || pinProtocol == PinProtocolVersion.VERSION_2) {
            "PIN Protocol version ${pinProtocol.value} is not supported"
        }
        // Expected pinAuth length: 16 bytes for v1, 32 bytes for v2
        val expectedPinAuthLength = when (pinProtocol) {
            PinProtocolVersion.VERSION_1 -> 16
            PinProtocolVersion.VERSION_2 -> 32
            else -> throw IllegalArgumentException("Unsupported PIN protocol version: ${pinProtocol.value}")
        }
        when (value.subCommand) {
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
                require(pinAuth.size == expectedPinAuthLength) {
                    "pinAuth must be $expectedPinAuthLength bytes length for PIN protocol ${pinProtocol.value}"
                }
            }
            PinSubCommand.CHANGE_PIN -> {
                requireNotNull(value.keyAgreement)
                requireNotNull(value.pinHashEnc)
                requireNotNull(value.newPinEnc)
                val pinAuth = value.pinAuth
                requireNotNull(pinAuth)
                require(pinAuth.size == expectedPinAuthLength) {
                    "pinAuth must be $expectedPinAuthLength bytes length for PIN protocol ${pinProtocol.value}"
                }
            }
            PinSubCommand.GET_PIN_TOKEN -> {
                requireNotNull(value.keyAgreement)
                requireNotNull(value.pinHashEnc)
            }
            //spec| getPinUvAuthTokenUsingUvWithPermissions (0x06)
            //spec| Platform sends:
            //spec|   pinUvAuthProtocol, keyAgreement, permissions
            PinSubCommand.GET_PIN_UV_AUTH_TOKEN_USING_UV_WITH_PERMISSIONS -> {
                requireNotNull(value.keyAgreement)
                requireNotNull(value.permissions)
            }
            //spec| getUVRetries (0x07)
            PinSubCommand.GET_UV_RETRIES -> {
                // nop - no required parameters beyond pinProtocol and subCommand
            }
            //spec| getPinUvAuthTokenUsingPinWithPermissions (0x09)
            //spec| Platform sends:
            //spec|   pinUvAuthProtocol, keyAgreement, pinHashEnc, permissions
            PinSubCommand.GET_PIN_UV_AUTH_TOKEN_USING_PIN_WITH_PERMISSIONS -> {
                requireNotNull(value.keyAgreement)
                requireNotNull(value.pinHashEnc)
                requireNotNull(value.permissions)
            }
        }
    }
}
