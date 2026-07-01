package com.webauthn4j.ctap.authenticator

import com.webauthn4j.data.PinProtocolVersion
import com.webauthn4j.ctap.core.util.internal.CipherUtil
import com.webauthn4j.ctap.core.util.internal.KeyAgreementUtil
import com.webauthn4j.data.attestation.authenticator.COSEKey
import com.webauthn4j.data.attestation.authenticator.EC2COSEKey
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier
import com.webauthn4j.util.ECUtil
import com.webauthn4j.util.MACUtil
import com.webauthn4j.util.MessageDigestUtil
import java.security.KeyPair
import java.security.SecureRandom
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.util.Arrays
import javax.crypto.spec.SecretKeySpec

/**
 * PIN/UV Auth Protocol version 1 implementation.
 *
 * Uses AES-256-CBC with a zero IV and HMAC-SHA-256 truncated to 16 bytes.
 * The shared secret is derived as SHA-256 of the raw ECDH shared secret.
 * The pinUvAuthToken is 16 bytes.
 *
 * @see <a href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#pinProto1">6.5.6. PIN/UV Auth Protocol One</a>
 */
class PinUvAuthProtocolV1 : PinUvAuthProtocol {

    companion object {
        private val ZERO_IV = byteArrayOf(
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        )
        private val ECDH_ES_HKDF_256 = COSEAlgorithmIdentifier.create(-25)
        private const val PIN_UV_AUTH_TOKEN_LENGTH = 16
        private const val HMAC_OUTPUT_LENGTH = 16
    }

    override val version: PinProtocolVersion = PinProtocolVersion.VERSION_1

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
    //spec|   Return SHA-256(Z)
    override fun decapsulate(peerCoseKey: COSEKey): ByteArray {
        val ecdhSecret = KeyAgreementUtil.generateSecret(
            keyAgreementKeyPair.private as ECPrivateKey,
            peerCoseKey.publicKey as ECPublicKey?
        )
        return MessageDigestUtil.createSHA256().digest(ecdhSecret)
    }

    //spec| encrypt(key, demPlaintext) → ciphertext
    //spec|   Return the AES-256-CBC encryption of demPlaintext using an all-zero IV.
    //spec|   (No padding is performed as the size of demPlaintext is required to be a multiple of the AES block length.)
    override fun encrypt(key: ByteArray, plaintext: ByteArray): ByteArray {
        val secretKey = SecretKeySpec(key, "AES")
        return CipherUtil.encryptWithAESCBCNoPadding(plaintext, secretKey, ZERO_IV)
    }

    //spec| decrypt(key, demCiphertext) → plaintext | error
    //spec|   If the size of demCiphertext is not a multiple of the AES block length, return error.
    //spec|   Otherwise return the AES-256-CBC decryption of demCiphertext using an all-zero IV.
    override fun decrypt(key: ByteArray, ciphertext: ByteArray): ByteArray {
        val secretKey = SecretKeySpec(key, "AES")
        return CipherUtil.decryptWithAESCBCNoPadding(ciphertext, secretKey, ZERO_IV)
    }

    //spec| authenticate(key, message) → signature
    //spec|   Return the first 16 bytes of the result of computing HMAC-SHA-256 with the given key and message.
    override fun authenticate(key: ByteArray, message: ByteArray): ByteArray {
        return MACUtil.calculateHmacSHA256(message, key, HMAC_OUTPUT_LENGTH)
    }

    //spec| verify(key, message, signature) → success | error
    //spec|   If the key parameter value is the current pinUvAuthToken and it is not in use, then return error.
    //spec|   Compute HMAC-SHA-256 with the given key and message.
    //spec|   Return success if signature is 16 bytes and is equal to the first 16 bytes of the result, otherwise return error.
    override fun verify(key: ByteArray, message: ByteArray, signature: ByteArray): Boolean {
        val expected = authenticate(key, message)
        return Arrays.equals(expected, signature)
    }
}
