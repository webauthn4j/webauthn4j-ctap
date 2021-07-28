package com.webauthn4j.ctap.core.data

class AuthenticatorMakeCredentialResponse :
    AbstractCtapResponse<AuthenticatorMakeCredentialResponseData> {
    constructor(
        statusCode: StatusCode,
        responseData: AuthenticatorMakeCredentialResponseData?
    ) : super(statusCode, responseData)

    constructor(statusCode: StatusCode) : super(statusCode, null)

    override val command: CtapCommand = CtapCommand.MAKE_CREDENTIAL

    override fun toString(): String {
        return "AuthenticatorMakeCredentialResponse(statusCode=$statusCode, responseData=$responseData)"
    }
}
