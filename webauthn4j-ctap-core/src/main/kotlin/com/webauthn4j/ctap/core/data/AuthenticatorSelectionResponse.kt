package com.webauthn4j.ctap.core.data

class AuthenticatorSelectionResponse(statusCode: CtapStatusCode) :
    AbstractCtapResponse<AuthenticatorSelectionResponseData>(statusCode) {

    override fun toString(): String {
        return "AuthenticatorSelectionResponse(statusCode=$statusCode, responseData=$responseData)"
    }
}
