package com.webauthn4j.ctap.core.data

class AuthenticatorGetAssertionResponse :
    AbstractCtapResponse<AuthenticatorGetAssertionResponseData> {
    constructor(
        statusCode: CtapStatusCode,
        responseData: AuthenticatorGetAssertionResponseData?
    ) : super(statusCode, responseData)

    constructor(statusCode: CtapStatusCode) : super(statusCode, null)

    //override val command: CtapCommand = CtapCommand.GET_ASSERTION

    override fun toString(): String {
        return "AuthenticatorGetAssertionResponse(statusCode=$statusCode, responseData=$responseData)"
    }
}
