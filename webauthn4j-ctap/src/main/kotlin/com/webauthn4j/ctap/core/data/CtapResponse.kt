package com.webauthn4j.ctap.core.data

interface CtapResponse<T : CtapResponseData> {
    val command: CtapCommand
    val statusCode: StatusCode
    val responseData: T?
}
