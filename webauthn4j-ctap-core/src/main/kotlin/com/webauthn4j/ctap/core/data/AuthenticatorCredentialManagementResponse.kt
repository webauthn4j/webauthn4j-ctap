package com.webauthn4j.ctap.core.data

class AuthenticatorCredentialManagementResponse : AbstractCtapResponse<AuthenticatorCredentialManagementResponseData> {
    constructor(
        statusCode: CtapStatusCode,
        responseData: AuthenticatorCredentialManagementResponseData?
    ) : super(
        statusCode,
        responseData
    )

    constructor(statusCode: CtapStatusCode) : super(statusCode, null)

    override fun toString(): String {
        return "AuthenticatorCredentialManagementResponse(statusCode=$statusCode, responseData=$responseData)"
    }
}
