package com.webauthn4j.ctap.authenticator

sealed interface BuiltInUserVerificationResult {
    data class Verified(val userPresent: Boolean) : BuiltInUserVerificationResult

    data object Invalid : BuiltInUserVerificationResult

    data object UserActionTimeout : BuiltInUserVerificationResult

    data object Blocked : BuiltInUserVerificationResult
}
