package com.webauthn4j.ctap.authenticator.execution

import com.webauthn4j.ctap.core.data.U2FStatusCode

class U2FCommandExecutionException @JvmOverloads constructor(
    val statusCode: U2FStatusCode,
    e: Throwable? = null
) : RuntimeException(e) {
    override val message: String
        get() = statusCode.toString()
}