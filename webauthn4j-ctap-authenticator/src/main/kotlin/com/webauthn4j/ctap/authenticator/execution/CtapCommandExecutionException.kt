package com.webauthn4j.ctap.authenticator.execution

import com.webauthn4j.ctap.core.data.CtapStatusCode

class CtapCommandExecutionException @JvmOverloads constructor(
    val statusCode: CtapStatusCode,
    e: Throwable? = null
) : RuntimeException(e) {
    override val message: String
        get() = statusCode.toString()
}