package com.webauthn4j.ctap.authenticator

import com.webauthn4j.data.PinProtocolVersion
import com.webauthn4j.ctap.core.util.internal.CipherUtil
import com.webauthn4j.ctap.core.util.internal.KeyAgreementUtil
import com.webauthn4j.data.attestation.authenticator.COSEKey
import com.webauthn4j.data.attestation.authenticator.EC2COSEKey
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier
import com.webauthn4j.util.ECUtil
import java.security.KeyPair
import java.security.SecureRandom
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.util.Arrays
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * PIN/UV Auth Protocol version 2 implementation.
 *
 * Key differences from v1:
 * - KDF uses HKDF-SHA-256 to derive separate HMAC key and AES key (64 bytes total)
 * - Encryption uses a random IV prepended to the ciphertext
 * - HMAC-SHA-256 output is not truncated (full 32 bytes)
 * - pinUvAuthToken is 32 bytes
 *
 * @see <a href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#pinProto2">6.5.7. PIN/UV Auth Protocol Two</a>
 */
class PinUvAuthProtocolV2 : PinUvAuthProtocol {

    companion object {
        private val ECDH_ES_HKDF_256 = COSEAlgorithmIdentifier.create(-25)
        private const val PIN_UV_AUTH_TOKEN_LENGTH = 32
        private const val HMAC_KEY_LENGTH = 32
        private const val AES_KEY_LENGTH = 32
        private const val IV_LENGTH = 16
        private val HKDF_SALT = ByteArray(32) // 32 zero bytes
        private val HMAC_KEY_INFO = "CTAP2 HMAC key".toByteArray(Charsets.UTF_8)
        private val AES_KEY_INFO = "CTAP2 AES key".toByteArray(Charsets.UTF_8)
    }

    override val version: PinProtocolVersion = PinProtocolVersion.VERSION_2

    private var keyAgreementKeyPair: KeyPair = ECUtil.createKeyPair()
    private var _pinUvAuthToken: ByteArray = ByteArray(PIN_UV_AUTH_TOKEN_LENGTH)

    override val pinUvAuthToken: ByteArray
        get() = _pinUvAuthToken.copyOf()

    init {
        SecureRandom().nextBytes(_pinUvAuthToken)
    }

    override fun initialize() {
        keyAgreementKeyPair = ECUtil.createKeyPair()
        resetPinUvAuthToken()
    }

    override fun regenerate() {
        keyAgreementKeyPair = ECUtil.createKeyPair()
    }

    override fun resetPinUvAuthToken() {
        _pinUvAuthToken = ByteArray(PIN_UV_AUTH_TOKEN_LENGTH)
        SecureRandom().nextBytes(_pinUvAuthToken)
    }

    override fun getPublicKey(): COSEKey {
        return EC2COSEKey.create(
            keyAgreementKeyPair.public as ECPublicKey,
            ECDH_ES_HKDF_256
        )
    }

    //spec| kdf(Z) → sharedSecret
    //spec|   Return
    //spec|   HKDF-SHA-256(salt = 32 zero bytes, IKM = Z, L = 32, info = "CTAP2 HMAC key") ||
    //spec|   HKDF-SHA-256(salt = 32 zero bytes, IKM = Z, L = 32, info = "CTAP2 AES key")
    override fun decapsulate(peerCoseKey: COSEKey): ByteArray {
        val ecdhSecret = KeyAgreementUtil.generateSecret(
            keyAgreementKeyPair.private as ECPrivateKey,
            peerCoseKey.publicKey as ECPublicKey?
        )
        val hmacKey = hkdfSha256(HKDF_SALT, ecdhSecret, HMAC_KEY_INFO, HMAC_KEY_LENGTH)
        val aesKey = hkdfSha256(HKDF_SALT, ecdhSecret, AES_KEY_INFO, AES_KEY_LENGTH)
        return hmacKey + aesKey
    }

    //spec| encrypt(key, demPlaintext) → ciphertext
    //spec|   Discard the first 32 bytes of key. (This selects the AES-key portion of the shared secret.)
    //spec|   Let iv be a 16-byte, random bytestring.
    //spec|   Let ct be the AES-256-CBC encryption of demPlaintext using key and iv.
    //spec|   (No padding is performed as the size of demPlaintext is required to be a multiple of the AES block length.)
    //spec|   Return iv || ct.
    override fun encrypt(key: ByteArray, plaintext: ByteArray): ByteArray {
        val aesKey = key.copyOfRange(HMAC_KEY_LENGTH, HMAC_KEY_LENGTH + AES_KEY_LENGTH)
        val iv = ByteArray(IV_LENGTH)
        SecureRandom().nextBytes(iv)
        val secretKey = SecretKeySpec(aesKey, "AES")
        val ciphertext = CipherUtil.encryptWithAESCBCNoPadding(plaintext, secretKey, iv)
        return iv + ciphertext
    }

    //spec| decrypt(key, demCiphertext) → plaintext | error
    //spec|   Discard the first 32 bytes of key. (This selects the AES-key portion of the shared secret.)
    //spec|   If demPlaintext is less than 16 bytes in length, return an error
    //spec|   Split demPlaintext after the 16th byte to produce two subspans, iv and ct.
    //spec|   Return the AES-256-CBC decryption of ct using key and iv.
    override fun decrypt(key: ByteArray, ciphertext: ByteArray): ByteArray {
        val aesKey = key.copyOfRange(HMAC_KEY_LENGTH, HMAC_KEY_LENGTH + AES_KEY_LENGTH)
        val iv = ciphertext.copyOfRange(0, IV_LENGTH)
        val ct = ciphertext.copyOfRange(IV_LENGTH, ciphertext.size)
        val secretKey = SecretKeySpec(aesKey, "AES")
        return CipherUtil.decryptWithAESCBCNoPadding(ct, secretKey, iv)
    }

    //spec| authenticate(key, message) → signature
    //spec|   If key is longer than 32 bytes, discard the excess.
    //spec|   (This selects the HMAC-key portion of the shared secret.
    //spec|   When key is the pinUvAuthToken, it is exactly 32 bytes long and thus this step has no effect.)
    //spec|   Return the result of computing HMAC-SHA-256 on key and message.
    override fun authenticate(key: ByteArray, message: ByteArray): ByteArray {
        val hmacKey = key.copyOfRange(0, HMAC_KEY_LENGTH)
        return hmacSha256(hmacKey, message)
    }

    //spec| verify(key, message, signature) → success | error
    //spec|   If the key parameter value is the current pinUvAuthToken and it is not in use, then return error.
    //spec|   If key is longer than 32 bytes, discard the excess.
    //spec|   (This selects the HMAC-key portion of the shared secret.
    //spec|   When key is the pinUvAuthToken, it is exactly 32 bytes long and thus this step has no effect.)
    //spec|   Compute HMAC-SHA-256 with the given key and message.
    //spec|   Return success if the signature is equal to the result, otherwise return an error.
    override fun verify(key: ByteArray, message: ByteArray, signature: ByteArray): Boolean {
        val expected = authenticate(key, message)
        return Arrays.equals(expected, signature)
    }

    /**
     * HKDF-SHA-256 implementation.
     * HKDF-Extract: PRK = HMAC-SHA-256(salt, IKM)
     * HKDF-Expand: OKM = HMAC-SHA-256(PRK, info || 0x01) truncated to L bytes
     * Since L=32 equals the hash output length, only one iteration is needed.
     */
    private fun hkdfSha256(salt: ByteArray, ikm: ByteArray, info: ByteArray, length: Int): ByteArray {
        // HKDF-Extract
        val prk = hmacSha256(salt, ikm)
        // HKDF-Expand (single iteration since L <= HashLen)
        val expandInput = info + byteArrayOf(0x01)
        val okm = hmacSha256(prk, expandInput)
        return okm.copyOf(length)
    }

    /**
     * Compute HMAC-SHA-256.
     */
    private fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        val secretKeySpec = SecretKeySpec(key, "HmacSHA256")
        mac.init(secretKeySpec)
        return mac.doFinal(data)
    }
}
