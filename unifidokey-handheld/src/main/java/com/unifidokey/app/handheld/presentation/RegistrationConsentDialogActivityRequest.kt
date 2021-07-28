package com.unifidokey.app.handheld.presentation

import com.webauthn4j.data.PublicKeyCredentialRpEntity
import com.webauthn4j.data.PublicKeyCredentialUserEntity
import java.io.Serializable

data class RegistrationConsentDialogActivityRequest(
    val user: PublicKeyCredentialUserEntity,
    val rp: PublicKeyCredentialRpEntity,
    val isUserPresence: Boolean,
    val isUserVerification: Boolean
) : Serializable
