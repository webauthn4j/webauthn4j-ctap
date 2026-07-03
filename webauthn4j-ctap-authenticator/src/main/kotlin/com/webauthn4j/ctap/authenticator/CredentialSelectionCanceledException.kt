package com.webauthn4j.ctap.authenticator

class CredentialSelectionCanceledException : RuntimeException {
    constructor(message: String?, cause: Throwable?) : super(message, cause)
    constructor(message: String?) : super(message)
    constructor(cause: Throwable?) : super(cause)
}
