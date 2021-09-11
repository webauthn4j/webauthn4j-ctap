package com.webauthn4j.ctap.authenticator.exception

import com.webauthn4j.ctap.core.data.U2FStatusCode

class APDUProcessingException @JvmOverloads constructor(
    val statusCode: U2FStatusCode,
    e: Throwable? = null
) : RuntimeException(e) {
    override val message: String
        get() = statusCode.toString()
}