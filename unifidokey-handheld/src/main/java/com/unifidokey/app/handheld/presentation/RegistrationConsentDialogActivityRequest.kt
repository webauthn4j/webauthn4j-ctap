package com.unifidokey.app.handheld.presentation

import com.webauthn4j.ctap.core.data.CtapPublicKeyCredentialRpEntity
import com.webauthn4j.ctap.core.data.CtapPublicKeyCredentialUserEntity
import com.webauthn4j.data.PublicKeyCredentialRpEntity
import com.webauthn4j.data.PublicKeyCredentialUserEntity
import java.io.Serializable

data class RegistrationConsentDialogActivityRequest(
    val user: CtapPublicKeyCredentialUserEntity?,
    val rp: CtapPublicKeyCredentialRpEntity?,
    val isUserPresence: Boolean,
    val isUserVerification: Boolean
) : Serializable
