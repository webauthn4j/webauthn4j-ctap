package com.webauthn4j.ctap.authenticator

fun interface BuiltInUserVerificationHandler {
    /** Performs one built-in user-verification attempt. */
    suspend fun performBuiltInUserVerification(): BuiltInUserVerificationAttemptResult
}
