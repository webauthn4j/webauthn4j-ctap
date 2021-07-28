package com.webauthn4j.ctap.client.exception

import com.webauthn4j.ctap.core.data.StatusCode

class CtapErrorException @JvmOverloads constructor(
    val statusCode: StatusCode,
    e: Throwable? = null
) : CtapClientException(e) {
    override val message: String
        get() = statusCode.toString()
}