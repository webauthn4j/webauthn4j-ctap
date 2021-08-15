package com.webauthn4j.ctap.core.data

class AuthenticatorResetResponse(statusCode: CtapStatusCode) :
    AbstractCtapResponse<AuthenticatorResetResponseData>(statusCode) {

    override val command: CtapCommand = CtapCommand.RESET

    override fun toString(): String {
        return "AuthenticatorResetResponse(statusCode=$statusCode, responseData=$responseData)"
    }
}
