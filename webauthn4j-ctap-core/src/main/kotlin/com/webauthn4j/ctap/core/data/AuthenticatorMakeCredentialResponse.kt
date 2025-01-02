package com.webauthn4j.ctap.core.data

class AuthenticatorMakeCredentialResponse :
    AbstractCtapResponse<AuthenticatorMakeCredentialResponseData> {
    constructor(
        statusCode: CtapStatusCode,
        responseData: AuthenticatorMakeCredentialResponseData?
    ) : super(statusCode, responseData)

    constructor(statusCode: CtapStatusCode) : super(statusCode, null)

    //override val command: CtapCommand = CtapCommand.MAKE_CREDENTIAL

    override fun toString(): String {
        return "AuthenticatorMakeCredentialResponse(statusCode=$statusCode, responseData=$responseData)"
    }
}
