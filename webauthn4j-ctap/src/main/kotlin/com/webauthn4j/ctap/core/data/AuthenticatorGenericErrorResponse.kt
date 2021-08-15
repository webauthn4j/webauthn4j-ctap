package com.webauthn4j.ctap.core.data

class AuthenticatorGenericErrorResponse(override val command: CtapCommand, statusCode: CtapStatusCode) :
    AbstractCtapResponse<CtapResponseData>(statusCode) {

    override fun toString(): String {
        return "AuthenticatorGenericErrorResponse(statusCode=$statusCode, responseData=$responseData)"
    }

}
