package com.webauthn4j.ctap.core.data

class AuthenticatorClientPINResponse : AbstractCtapResponse<AuthenticatorClientPINResponseData> {
    constructor(statusCode: CtapStatusCode, responseData: AuthenticatorClientPINResponseData?) : super(
        statusCode,
        responseData
    )

    constructor(statusCode: CtapStatusCode) : super(statusCode, null)

    override val command: CtapCommand = CtapCommand.CLIENT_PIN

    override fun toString(): String {
        return "AuthenticatorClientPINResponse(statusCode=$statusCode, responseData=$responseData)"
    }
}
