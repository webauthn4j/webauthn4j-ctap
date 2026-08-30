package com.webauthn4j.ctap.core.data

class AuthenticatorConfigResponse(statusCode: CtapStatusCode) :
    AbstractCtapResponse<AuthenticatorConfigResponseData>(statusCode) {

    override fun toString(): String {
        return "AuthenticatorConfigResponse(statusCode=$statusCode, responseData=$responseData)"
    }
}
