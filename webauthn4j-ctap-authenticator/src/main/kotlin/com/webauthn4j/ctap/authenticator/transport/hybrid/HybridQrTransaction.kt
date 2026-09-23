package com.webauthn4j.ctap.authenticator.transport.hybrid

import java.security.SecureRandom
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/** Phone-side QR transaction material. This class has no Bluetooth or WebSocket dependency. */
class HybridQrTransaction(
    val qr: HybridQrPayload,
    val routingId: ByteArray = ByteArray(3).also { SecureRandom().nextBytes(it) },
    val nonce: ByteArray = ByteArray(10).also { SecureRandom().nextBytes(it) },
    val encodedTunnelDomain: Int = 0,
) {
    init {
        require(routingId.size == 3) { "Hybrid routing ID must contain three bytes" }
        require(nonce.size == 10) { "Hybrid advertisement nonce must contain ten bytes" }
        require(encodedTunnelDomain in 0..65535) { "Hybrid tunnel domain must fit in two bytes" }
    }

    val advertisementPlaintext: ByteArray = byteArrayOf(0) + nonce + routingId +
        byteArrayOf(encodedTunnelDomain.toByte(), (encodedTunnelDomain shr 8).toByte())

    val tunnelId: ByteArray get() = derive(2).copyOfRange(0, 16)
    val noisePsk: ByteArray get() = derive(3, advertisementPlaintext).copyOfRange(0, 32)
    val tunnelDomain: String get() = decodeDomain(encodedTunnelDomain)
    val tunnelPath: String get() = "/cable/connect/${routingId.toHex()}/${tunnelId.toHex()}"

    /** FFF9 service data: AES-256 encrypted EID followed by a four-byte HMAC tag. */
    val advertisement: ByteArray get() {
        val eidKey = derive(1)
        val cipher = Cipher.getInstance("AES/ECB/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(eidKey.copyOfRange(0, 32), "AES"))
        val encrypted = cipher.doFinal(advertisementPlaintext)
        val tag = hmac(eidKey.copyOfRange(32, 64), encrypted)
        return encrypted + tag.copyOfRange(0, 4)
    }

    private fun derive(purpose: Byte, salt: ByteArray? = null): ByteArray {
        // HKDF-SHA256 with four-byte, little-endian purpose labels.
        val prk = hmac(salt ?: ByteArray(32), qr.secret)
        val info = byteArrayOf(purpose, 0, 0, 0)
        val first = hmac(prk, info + byteArrayOf(1))
        val second = hmac(prk, first + info + byteArrayOf(2))
        return first + second
    }

    private fun derive(purpose: Int, salt: ByteArray? = null): ByteArray = derive(purpose.toByte(), salt)

    private fun hmac(key: ByteArray, value: ByteArray): ByteArray = Mac.getInstance("HmacSHA256").run {
        init(SecretKeySpec(key, "HmacSHA256"))
        doFinal(value)
    }

    private fun decodeDomain(encoded: Int): String {
        val known = listOf("cable.ua5v.com", "cable.auth.com")
        if (encoded < known.size) return known[encoded]
        val digest = MessageDigest.getInstance("SHA-256").digest(
            "caBLEv2 tunnel server domain".toByteArray(Charsets.US_ASCII) +
                byteArrayOf(encoded.toByte(), (encoded shr 8).toByte(), 0),
        )
        var value = digest.take(8).foldIndexed(0uL) { index, sum, byte ->
            sum or (byte.toUByte().toULong() shl (index * 8))
        }
        val suffix = listOf(".com", ".org", ".net", ".info")[(value and 3uL).toInt()]
        value = value shr 2
        val alphabet = "abcdefghijklmnopqrstuvwxyz234567"
        val name = StringBuilder("cable.")
        while (value != 0uL) {
            name.append(alphabet[(value and 31uL).toInt()])
            value = value shr 5
        }
        return name.append(suffix).toString()
    }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it.toInt() and 255) }
}
