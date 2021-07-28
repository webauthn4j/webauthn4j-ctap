package com.webauthn4j.ctap.authenticator

import java.io.Serializable

data class GetAssertionConsentOptions(
    val rpId: String,
    val isUserPresence: Boolean,
    val isUserVerification: Boolean
) : Serializable
