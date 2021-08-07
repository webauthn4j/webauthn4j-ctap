package com.webauthn4j.ctap.core.data

class AuthenticatorGetNextAssertionResponse :
    AbstractCtapResponse<AuthenticatorGetNextAssertionResponseData> {
    constructor(
        statusCode: StatusCode,
        responseData: AuthenticatorGetNextAssertionResponseData?
    ) : super(statusCode, responseData)

    constructor(statusCode: StatusCode) : super(statusCode, null)

    override val command: CtapCommand = CtapCommand.GET_NEXT_ASSERTION

    override fun toString(): String {
        return "AuthenticatorGetNextAssertionResponse(statusCode=$statusCode, responseData=$responseData)"
    }
}