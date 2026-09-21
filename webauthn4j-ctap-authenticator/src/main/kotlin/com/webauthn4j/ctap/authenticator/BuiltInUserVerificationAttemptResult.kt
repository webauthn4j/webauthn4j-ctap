package com.webauthn4j.ctap.authenticator

sealed interface BuiltInUserVerificationAttemptResult {
    data class Verified(val userPresent: Boolean) : BuiltInUserVerificationAttemptResult

    data object Invalid : BuiltInUserVerificationAttemptResult

    data object UserActionTimeout : BuiltInUserVerificationAttemptResult
}
