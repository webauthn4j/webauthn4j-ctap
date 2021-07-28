package com.webauthn4j.ctap.core.data

class AuthenticatorClientPINResponse : AbstractCtapResponse<AuthenticatorClientPINResponseData> {
    constructor(statusCode: StatusCode, responseData: AuthenticatorClientPINResponseData?) : super(
        statusCode,
        responseData
    )

    constructor(statusCode: StatusCode) : super(statusCode, null)

    override val command: CtapCommand = CtapCommand.CLIENT_PIN

    override fun toString(): String {
        return "AuthenticatorClientPINResponse(statusCode=$statusCode, responseData=$responseData)"
    }
}
