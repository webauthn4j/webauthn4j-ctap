package com.webauthn4j.ctap.client.exception

class ClientPINUserVerificationCanceledException : RuntimeException {
    constructor(message: String?, cause: Throwable?) : super(message, cause)
    constructor(message: String?) : super(message)
    constructor(cause: Throwable?) : super(cause)
}