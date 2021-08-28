package com.webauthn4j.ctap.client

import com.webauthn4j.ctap.core.data.CtapPublicKeyCredentialUserEntity
import com.webauthn4j.data.PublicKeyCredentialDescriptor

data class GetAssertionsResponse(val assertions: List<Assertion>) {

    data class Assertion(
        val credential: PublicKeyCredentialDescriptor?,
        val authData: ByteArray,
        val signature: ByteArray,
        val user: CtapPublicKeyCredentialUserEntity?
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false

            other as Assertion

            if (credential != other.credential) return false
            if (!authData.contentEquals(other.authData)) return false
            if (!signature.contentEquals(other.signature)) return false
            if (user != other.user) return false

            return true
        }

        override fun hashCode(): Int {
            var result = credential?.hashCode() ?: 0
            result = 31 * result + authData.contentHashCode()
            result = 31 * result + signature.contentHashCode()
            result = 31 * result + (user?.hashCode() ?: 0)
            return result
        }
    }
}