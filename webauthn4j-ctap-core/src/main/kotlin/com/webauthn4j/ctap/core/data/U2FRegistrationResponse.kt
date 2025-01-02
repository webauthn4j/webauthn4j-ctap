package com.webauthn4j.ctap.core.data

import com.webauthn4j.ctap.core.util.internal.HexUtil
import com.webauthn4j.data.attestation.statement.AttestationCertificate
import com.webauthn4j.util.ArrayUtil
import com.webauthn4j.util.ECUtil
import java.nio.ByteBuffer
import java.security.interfaces.ECPublicKey

class U2FRegistrationResponse : AuthenticatorResponse {

    @Suppress("JoinDeclarationAndAssignment")
    val reservedByte: Byte
    val userPublicKey: ECPublicKey
    val keyHandle: ByteArray
        get() = ArrayUtil.clone(field)
    val attestationCertificate: AttestationCertificate
    val signature: ByteArray
        get() = ArrayUtil.clone(field)

    constructor(
        reserved: Byte,
        userPublicKey: ECPublicKey,
        keyHandle: ByteArray,
        attestationCertificate: AttestationCertificate,
        signature: ByteArray
    ) {
        this.reservedByte = reserved
        this.userPublicKey = userPublicKey
        this.keyHandle = ArrayUtil.clone(keyHandle)
        this.attestationCertificate = attestationCertificate
        this.signature = ArrayUtil.clone(signature)
    }

    fun toBytes(): ByteArray {
        val attestationCertificateBytes = attestationCertificate.certificate.encoded
        val publicKey = ECUtil.createUncompressedPublicKey(userPublicKey)
        val keyHandleSize = keyHandle.size.toUByte()
        val length = 1 + 65 + 1 + keyHandle.size + attestationCertificateBytes.size + signature.size
        return ByteBuffer.allocate(length).put(reservedByte).put(publicKey)
            .put(keyHandleSize.toByte()).put(keyHandle).put(attestationCertificateBytes)
            .put(signature).array()
    }


    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is U2FRegistrationResponse) return false

        if (reservedByte != other.reservedByte) return false
        if (userPublicKey != other.userPublicKey) return false
        if (!keyHandle.contentEquals(other.keyHandle)) return false
        if (attestationCertificate != other.attestationCertificate) return false
        if (!signature.contentEquals(other.signature)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = reservedByte.hashCode()
        result = 31 * result + userPublicKey.hashCode()
        result = 31 * result + keyHandle.contentHashCode()
        result = 31 * result + attestationCertificate.hashCode()
        result = 31 * result + signature.contentHashCode()
        return result
    }

    override fun toString(): String {
        return "U2FRegistrationResponse(reservedByte=$reservedByte, userPublicKey=${
            HexUtil.encodeToString(
                ECUtil.createUncompressedPublicKey(userPublicKey)
            )
        }, keyHandle=${HexUtil.encodeToString(keyHandle)}, attestationCertificate=${attestationCertificate.certificate.subjectX500Principal}, signature=${
            HexUtil.encodeToString(
                signature
            )
        })"
    }


}