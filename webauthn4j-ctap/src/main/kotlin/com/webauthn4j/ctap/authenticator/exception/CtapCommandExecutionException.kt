package com.webauthn4j.ctap.authenticator.exception

import com.webauthn4j.ctap.core.data.StatusCode

class CtapCommandExecutionException @JvmOverloads constructor(
    val statusCode: StatusCode,
    e: Throwable? = null
) : RuntimeException(e) {
    override val message: String
        get() = statusCode.toString()
}