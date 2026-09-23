package com.webauthn4j.ctap.authenticator.transport.hybrid

import org.bouncycastle.asn1.sec.SECNamedCurves
import java.math.BigInteger
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** QR-initiated Noise_KNpsk0_P256_AESGCM_SHA256 responder, independent of any socket or OS. */
class HybridNoiseResponder(
    initiatorStaticPublicKey: ByteArray,
    pskBytes: ByteArray,
    ephemeralPrivateKeyBytes: ByteArray = randomScalar(),
) {
    private val initiatorStatic = uncompressedPoint(initiatorStaticPublicKey)
    private val psk = pskBytes.copyOf()
    private val ephemeralPrivateKey = ephemeralPrivateKeyBytes.copyOf()
    private var used = false

    init {
        require(psk.size == 32) { "Hybrid Noise PSK must contain 32 bytes" }
        require(ephemeralPrivateKey.size == 32) { "Hybrid Noise private key must contain 32 bytes" }
        scalar(ephemeralPrivateKey)
    }

    @Synchronized
    fun accept(initialMessage: ByteArray): Pair<ByteArray, HybridNoiseTransport> {
        check(!used) { "Hybrid Noise responder is bound to one QR transaction" }
        used = true
        require(initialMessage.size == 81) { "Hybrid Noise initiator message must contain a P-256 point and tag" }
        val symmetric = SymmetricState()
        symmetric.mixHash(byteArrayOf(1))
        symmetric.mixHash(initiatorStatic)
        symmetric.mixKeyAndHash(psk)

        val initiatorEphemeral = uncompressedPoint(initialMessage.copyOfRange(0, 65))
        symmetric.mixHash(initiatorEphemeral)
        symmetric.mixKey(initiatorEphemeral)
        require(symmetric.decryptAndHash(initialMessage.copyOfRange(65, initialMessage.size)).isEmpty()) {
            "Hybrid Noise initiator payload must be empty"
        }

        val responderEphemeral = publicKey(ephemeralPrivateKey)
        symmetric.mixHash(responderEphemeral)
        symmetric.mixKey(responderEphemeral)
        symmetric.mixKey(dh(ephemeralPrivateKey, initiatorEphemeral)) // ee
        symmetric.mixKey(dh(ephemeralPrivateKey, initiatorStatic)) // se
        val response = responderEphemeral + symmetric.encryptAndHash(byteArrayOf())
        val (initiatorToResponder, responderToInitiator) = symmetric.split()
        return response to HybridNoiseTransport(responderToInitiator, initiatorToResponder)
    }

    private class SymmetricState {
        private var hash = ByteArray(32).also { destination ->
            PROTOCOL_NAME.toByteArray(Charsets.US_ASCII).copyInto(destination)
        }
        private var chainingKey = hash.copyOf()
        private var cipherKey: ByteArray? = null
        private var nonce = 0L

        fun mixHash(data: ByteArray) {
            hash = sha256(hash + data)
        }

        fun mixKey(data: ByteArray) {
            val keys = hkdf(chainingKey, data, 2)
            chainingKey = keys[0]
            cipherKey = keys[1]
            nonce = 0
        }

        fun mixKeyAndHash(data: ByteArray) {
            val keys = hkdf(chainingKey, data, 3)
            chainingKey = keys[0]
            mixHash(keys[1])
            cipherKey = keys[2]
            nonce = 0
        }

        fun encryptAndHash(plaintext: ByteArray): ByteArray {
            val encoded = cipherKey?.let { aesGcm(it, nonce++, hash, plaintext, true) } ?: plaintext
            mixHash(encoded)
            return encoded
        }

        fun decryptAndHash(ciphertext: ByteArray): ByteArray {
            val decoded = cipherKey?.let { aesGcm(it, nonce++, hash, ciphertext, false) } ?: ciphertext
            mixHash(ciphertext)
            return decoded
        }

        fun split(): Pair<ByteArray, ByteArray> {
            val keys = hkdf(chainingKey, byteArrayOf(), 2)
            return keys[0] to keys[1]
        }
    }

    companion object {
        private const val PROTOCOL_NAME = "Noise_KNpsk0_P256_AESGCM_SHA256"
        private val curve = SECNamedCurves.getByName("secp256r1")

        private fun randomScalar(): ByteArray {
            val random = SecureRandom()
            while (true) {
                val bytes = ByteArray(32).also(random::nextBytes)
                if (BigInteger(1, bytes) in BigInteger.ONE..<curve.n) return bytes
            }
        }

        private fun scalar(bytes: ByteArray): BigInteger = BigInteger(1, bytes).also {
            require(it >= BigInteger.ONE && it < curve.n) { "Invalid P-256 private key" }
        }

        private fun uncompressedPoint(bytes: ByteArray): ByteArray {
            val point = curve.curve.decodePoint(bytes).normalize()
            require(!point.isInfinity && point.isValid) { "Invalid P-256 public key" }
            return point.getEncoded(false)
        }

        private fun publicKey(privateKey: ByteArray): ByteArray =
            curve.g.multiply(scalar(privateKey)).normalize().getEncoded(false)

        private fun dh(privateKey: ByteArray, publicKey: ByteArray): ByteArray {
            val shared = curve.curve.decodePoint(publicKey).multiply(scalar(privateKey)).normalize()
            require(!shared.isInfinity && shared.isValid) { "Invalid P-256 ECDH result" }
            val x = shared.affineXCoord.toBigInteger().toByteArray().takeLast(32).toByteArray()
            return ByteArray(32 - x.size) + x
        }

        private fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)

        private fun hmac(key: ByteArray, bytes: ByteArray): ByteArray = Mac.getInstance("HmacSHA256").run {
            init(SecretKeySpec(key, "HmacSHA256"))
            doFinal(bytes)
        }

        private fun hkdf(salt: ByteArray, input: ByteArray, count: Int): List<ByteArray> {
            val prk = hmac(salt, input)
            val output = ArrayList<ByteArray>(count)
            var previous = byteArrayOf()
            for (index in 1..count) {
                previous = hmac(prk, previous + byteArrayOf(index.toByte()))
                output.add(previous)
            }
            return output
        }

        private fun aesGcm(key: ByteArray, nonce: Long, aad: ByteArray, input: ByteArray, encrypt: Boolean): ByteArray {
            val iv = ByteArray(12)
            for (index in 0..7) iv[4 + index] = (nonce ushr (56 - index * 8)).toByte()
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(
                if (encrypt) Cipher.ENCRYPT_MODE else Cipher.DECRYPT_MODE,
                SecretKeySpec(key, "AES"),
                GCMParameterSpec(128, iv),
            )
            cipher.updateAAD(aad)
            return cipher.doFinal(input)
        }
    }
}

/** Directional transport keys after a successful Hybrid Noise handshake. */
class HybridNoiseTransport internal constructor(
    private val sendingKey: ByteArray,
    private val receivingKey: ByteArray,
) {
    private var sendNonce = 0L
    private var receiveNonce = 0L

    fun encrypt(plaintext: ByteArray): ByteArray {
        require(plaintext.isNotEmpty() && plaintext.size <= 1024 * 1024) { "Hybrid frame is empty or too large" }
        val padding = 32 - plaintext.size % 32
        val padded = plaintext + ByteArray(padding).also { it[it.lastIndex] = (padding - 1).toByte() }
        return crypt(sendingKey, sendNonce++, padded, true)
    }

    fun decrypt(ciphertext: ByteArray): ByteArray {
        require(ciphertext.size in 17..(1024 * 1024 + 64)) { "Hybrid frame is empty or too large" }
        val padded = crypt(receivingKey, receiveNonce++, ciphertext, false)
        val padding = padded.last().toInt() and 0xff
        require(padding < padded.size) { "Invalid Hybrid padding" }
        return padded.copyOfRange(0, padded.size - padding - 1)
    }

    private fun crypt(key: ByteArray, nonce: Long, input: ByteArray, encrypt: Boolean): ByteArray {
        val iv = ByteArray(12)
        for (index in 0..7) iv[4 + index] = (nonce ushr (56 - index * 8)).toByte()
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(
            if (encrypt) Cipher.ENCRYPT_MODE else Cipher.DECRYPT_MODE,
            SecretKeySpec(key, "AES"),
            GCMParameterSpec(128, iv),
        )
        return cipher.doFinal(input)
    }
}
