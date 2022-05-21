package com.webauthn4j.ctap.core.data

class AuthenticatorGenericErrorResponse(statusCode: CtapStatusCode) :
    AbstractCtapResponse<CtapResponseData>(statusCode) {

    override fun toString(): String {
        return "AuthenticatorGenericErrorResponse(statusCode=$statusCode, responseData=$responseData)"
    }

}
