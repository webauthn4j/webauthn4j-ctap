package com.webauthn4j.ctap.core.data

import com.webauthn4j.data.PublicKeyCredentialDescriptor
import com.webauthn4j.data.PublicKeyCredentialUserEntity

interface AssertionResponseData : CtapResponseData {
    val credential: PublicKeyCredentialDescriptor?
    val authData: ByteArray?
    val signature: ByteArray?
    val user: CtapPublicKeyCredentialUserEntity?
}
