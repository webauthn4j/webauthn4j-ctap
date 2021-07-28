package com.webauthn4j.ctap.core.data

class AuthenticatorGetInfoResponse : AbstractCtapResponse<AuthenticatorGetInfoResponseData> {
    constructor(statusCode: StatusCode, responseData: AuthenticatorGetInfoResponseData?) : super(
        statusCode,
        responseData
    )

    constructor(statusCode: StatusCode) : super(statusCode, null)

    override val command: CtapCommand = CtapCommand.GET_INFO

    override fun toString(): String {
        return "AuthenticatorGetInfoResponse(statusCode=$statusCode, responseData=$responseData)"
    }
}
