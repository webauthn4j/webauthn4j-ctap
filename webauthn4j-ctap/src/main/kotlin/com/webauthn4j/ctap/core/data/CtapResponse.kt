package com.webauthn4j.ctap.core.data

interface CtapResponse : AuthenticatorResponse {
    val command: CtapCommand
    val statusCode: CtapStatusCode
    val responseData: CtapResponseData?
}
