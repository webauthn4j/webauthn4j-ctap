package com.unifidokey.app.handheld.presentation

import java.io.Serializable

data class AuthenticationConsentDialogActivityRequest(
    val rpId: String,
    val isUserPresence: Boolean,
    val isUserVerification: Boolean
) : Serializable
