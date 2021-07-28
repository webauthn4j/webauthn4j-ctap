package com.webauthn4j.ctap.authenticator

import com.webauthn4j.data.PublicKeyCredentialRpEntity
import com.webauthn4j.data.PublicKeyCredentialUserEntity
import java.io.Serializable

data class MakeCredentialConsentOptions(
    val rp: PublicKeyCredentialRpEntity,
    val user: PublicKeyCredentialUserEntity,
    val isUserPresence: Boolean,
    val isUserVerification: Boolean
) : Serializable
