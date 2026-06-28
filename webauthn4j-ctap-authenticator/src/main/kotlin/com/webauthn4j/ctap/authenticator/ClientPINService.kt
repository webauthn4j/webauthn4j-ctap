package com.webauthn4j.ctap.authenticator

import com.webauthn4j.ctap.authenticator.execution.CtapCommandExecutionException
import com.webauthn4j.ctap.authenticator.store.AuthenticatorPropertyStore
import com.webauthn4j.ctap.core.data.AuthenticatorClientPINResponse
import com.webauthn4j.ctap.core.data.AuthenticatorClientPINResponseData
import com.webauthn4j.ctap.core.data.CtapStatusCode
import com.webauthn4j.ctap.core.util.internal.ArrayUtil
import com.webauthn4j.ctap.core.util.internal.CipherUtil
import com.webauthn4j.ctap.core.util.internal.KeyAgreementUtil
import com.webauthn4j.data.attestation.authenticator.COSEKey
import com.webauthn4j.data.attestation.authenticator.EC2COSEKey
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier
import com.webauthn4j.util.ECUtil
import com.webauthn4j.util.MACUtil
import com.webauthn4j.util.MessageDigestUtil
import java.nio.ByteBuffer
import java.security.SecureRandom
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.util.Arrays
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

// @see <a href="https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorClientPIN">5.5. authenticatorClientPIN</a>
class ClientPINService(private val authenticatorPropertyStore: AuthenticatorPropertyStore) {

    companion object {
        const val MAX_PIN_RETRIES: UInt = 8u
        const val MAX_VOLATILE_PIN_RETRIES = 3
        private val ZERO_IV = byteArrayOf(
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        )
        private val ECDH_ES_HKDF_256 = COSEAlgorithmIdentifier.create(-25)
    }

    //spec| 5.5.2 Authenticator Configuration Operations Upon Power Up
    //spec| Generate "authenticatorKeyAgreementKey":
    //spec| Generate an ECDH P-256 key pair called "authenticatorKeyAgreementKey"
    //spec| denoted by (a, aG) where "a" denotes the private key and "aG" denotes the public key.
    var authenticatorKeyAgreementKey = ECUtil.createKeyPair()

    //spec| Generate "pinToken":
    //spec| Generate a random integer of length which is multiple of 16 bytes (AES block length).
    val pinToken = ByteArray(16)

    private var volatilePinRetryCounter = MAX_VOLATILE_PIN_RETRIES

    init {
        SecureRandom().nextBytes(pinToken)
    }

    fun regenerateKeys() {
        authenticatorKeyAgreementKey = ECUtil.createKeyPair()
        SecureRandom().nextBytes(pinToken)
        volatilePinRetryCounter = MAX_VOLATILE_PIN_RETRIES
    }

    //spec| 5.5.3 Getting Retries from Authenticator
    //spec| Retries count is the number of attempts remaining before lockout.
    //spec| Authenticator responds back with retries.
    fun getPinRetries(): AuthenticatorClientPINResponse {
        val pinRetries = authenticatorPropertyStore.loadPINRetries()
        val responseData = AuthenticatorClientPINResponseData(null, null, pinRetries)
        return AuthenticatorClientPINResponse(CtapStatusCode.CTAP2_OK, responseData)
    }

    //spec| 5.5.4 Getting sharedSecret from Authenticator
    //spec| Authenticator responds back with public key of authenticatorKeyAgreementKey, "aG".
    fun getKeyAgreement(): AuthenticatorClientPINResponse {
        val keyAgreement = EC2COSEKey.create(
            (authenticatorKeyAgreementKey.public as ECPublicKey),
            ECDH_ES_HKDF_256
        )
        val responseData = AuthenticatorClientPINResponseData(keyAgreement, null, null)
        return AuthenticatorClientPINResponse(CtapStatusCode.CTAP2_OK, responseData)
    }

    //spec| 5.5.5 Setting a New PIN
    //spec| Authenticator performs following operations upon receiving the request:
    fun setPIN(
        platformKeyAgreementKey: COSEKey?,
        pinAuth: ByteArray?,
        newPinEnc: ByteArray?
    ): AuthenticatorClientPINResponse {

        //spec| If Authenticator does not receive mandatory parameters for this command,
        //spec| it returns CTAP2_ERR_MISSING_PARAMETER error.
        if (platformKeyAgreementKey == null || pinAuth == null || newPinEnc == null) {
            return AuthenticatorClientPINResponse(CtapStatusCode.CTAP2_ERR_MISSING_PARAMETER)
        }
        //spec| If a PIN has already been set, authenticator returns CTAP2_ERR_PIN_AUTH_INVALID error.
        if (isClientPINReady) {
            return AuthenticatorClientPINResponse(CtapStatusCode.CTAP2_ERR_PIN_AUTH_INVALID)
        }
        //spec| Authenticator generates "sharedSecret": SHA-256((abG).x) using private key of
        //spec| authenticatorKeyAgreementKey, "a" and public key of platformKeyAgreementKey, "bG".
        val sharedSecret = generateSharedSecret(platformKeyAgreementKey)

        //spec| Authenticator verifies pinAuth by generating LEFT(HMAC-SHA-256(sharedSecret, newPinEnc), 16)
        //spec| and matching against input pinAuth parameter.
        //spec| If pinAuth verification fails, authenticator returns CTAP2_ERR_PIN_AUTH_INVALID error.
        val mac = MACUtil.calculateHmacSHA256(newPinEnc, sharedSecret, 16)
        if (!Arrays.equals(mac, pinAuth)) {
            return AuthenticatorClientPINResponse(CtapStatusCode.CTAP2_ERR_PIN_AUTH_INVALID)
        }
        //spec| Authenticator decrypts newPinEnc using above "sharedSecret" producing newPin and
        //spec| checks newPin length against minimum PIN length of 4 bytes.
        //spec| The decrypted padded newPin should be of at least 64 bytes length and authenticator
        //spec| determines actual PIN length by looking for first 0x00 byte which terminates the PIN.
        //spec| If minimum PIN length check fails, authenticator returns CTAP2_ERR_PIN_POLICY_VIOLATION error.
        val secretKey: SecretKey = SecretKeySpec(sharedSecret, "AES")
        val newPIN = CipherUtil.decryptWithAESCBCNoPadding(newPinEnc, secretKey, ZERO_IV)
        val sentinelPos = newPIN.indexOf(0x00)
        val trimmedNewPIN: ByteArray = when {
            (sentinelPos < 0) -> newPIN
            else -> newPIN.copyOf(sentinelPos)
        }
        if (trimmedNewPIN.size < 4) {
            return AuthenticatorClientPINResponse(CtapStatusCode.CTAP2_ERR_PIN_POLICY_VIOLATION)
        }
        if (trimmedNewPIN.size > 63) {
            return AuthenticatorClientPINResponse(CtapStatusCode.CTAP2_ERR_PIN_POLICY_VIOLATION)
        }
        //spec| Authenticator stores LEFT(SHA-256(newPin), 16) on the device,
        //spec| sets the retries counter to 8, and returns CTAP2_OK.
        authenticatorPropertyStore.saveClientPIN(
            Arrays.copyOf(MessageDigestUtil.createSHA256().digest(trimmedNewPIN), 16)
        )
        authenticatorPropertyStore.savePINRetries(MAX_PIN_RETRIES)
        return AuthenticatorClientPINResponse(CtapStatusCode.CTAP2_OK)
    }

    //spec| 5.5.6 Changing existing PIN
    //spec| Authenticator performs following operations upon receiving the request:
    fun changePIN(
        platformKeyAgreementKey: COSEKey?,
        pinAuth: ByteArray?,
        newPinEnc: ByteArray?,
        pinHashEnc: ByteArray?
    ): AuthenticatorClientPINResponse {
        //spec| If Authenticator does not receive mandatory parameters for this command,
        //spec| it returns CTAP2_ERR_MISSING_PARAMETER error.
        if (platformKeyAgreementKey == null || pinAuth == null || newPinEnc == null || pinHashEnc == null) {
            return AuthenticatorClientPINResponse(CtapStatusCode.CTAP2_ERR_MISSING_PARAMETER)
        }
        //spec| If the retries counter is 0, return CTAP2_ERR_PIN_BLOCKED error.
        if (authenticatorPropertyStore.loadPINRetries() == 0u) {
            return AuthenticatorClientPINResponse(CtapStatusCode.CTAP2_ERR_PIN_BLOCKED)
        }
        //spec| Authenticator generates "sharedSecret": SHA-256((abG).x) using private key of
        //spec| authenticatorKeyAgreementKey, "a" and public key of platformKeyAgreementKey, "bG".
        val sharedSecret = generateSharedSecret(platformKeyAgreementKey)
        //spec| Authenticator verifies pinAuth by generating LEFT(HMAC-SHA-256(sharedSecret, newPinEnc || pinHashEnc), 16)
        //spec| and matching against input pinAuth parameter.
        //spec| If pinAuth verification fails, authenticator returns CTAP2_ERR_PIN_AUTH_INVALID error.
        val joined =
            ByteBuffer.allocate(newPinEnc.size + pinHashEnc.size).put(newPinEnc).put(pinHashEnc)
                .array()
        val mac = MACUtil.calculateHmacSHA256(joined, sharedSecret, 16)
        if (!Arrays.equals(mac, pinAuth)) {
            return AuthenticatorClientPINResponse(CtapStatusCode.CTAP2_ERR_PIN_AUTH_INVALID)
        }
        //spec| Authenticator decrements the retries counter by 1.
        authenticatorPropertyStore.savePINRetries(authenticatorPropertyStore.loadPINRetries() - 1u)

        //spec| Authenticator decrypts pinHashEnc and verifies against its internal stored LEFT(SHA-256(curPin), 16).
        val secretKey: SecretKey = SecretKeySpec(sharedSecret, "AES")
        val pinHash = CipherUtil.decryptWithAESCBCNoPadding(pinHashEnc, secretKey, ZERO_IV)
        val storedPinHash =
            authenticatorPropertyStore.loadClientPIN() ?: return AuthenticatorClientPINResponse(
                CtapStatusCode.CTAP2_ERR_PIN_NOT_SET
            )

        if (!Arrays.equals(pinHash, storedPinHash)) {
            //spec| If a mismatch is detected, the authenticator performs the following operations:
            //spec| Authenticator generates a new "authenticatorKeyAgreementKey".
            //spec| Generate a new ECDH P-256 key pair called "authenticatorKeyAgreementKey" denoted by
            //spec| (a, aG), where "a" denotes the private key and "aG" denotes the public key.
            authenticatorKeyAgreementKey = ECUtil.createKeyPair()
            volatilePinRetryCounter--
            //spec| Authenticator returns errors according to following conditions:
            //spec| If the retries counter is 0, return CTAP2_ERR_PIN_BLOCKED error.
            //spec| If the authenticator sees 3 consecutive mismatches, it returns CTAP2_ERR_PIN_AUTH_BLOCKED,
            //spec| indicating that power cycling is needed for further operations. This is done so that malware
            //spec| running on the platform should not be able to block the device without user interaction.
            //spec| Else return CTAP2_ERR_PIN_INVALID error.
            return when {
                authenticatorPropertyStore.loadPINRetries() == 0u ->
                    AuthenticatorClientPINResponse(CtapStatusCode.CTAP2_ERR_PIN_BLOCKED)
                volatilePinRetryCounter <= 0 ->
                    AuthenticatorClientPINResponse(CtapStatusCode.CTAP2_ERR_PIN_AUTH_BLOCKED)
                else ->
                    AuthenticatorClientPINResponse(CtapStatusCode.CTAP2_ERR_PIN_INVALID)
            }
        }
        //spec| Authenticator sets the retries counter to 8.
        authenticatorPropertyStore.savePINRetries(MAX_PIN_RETRIES)
        volatilePinRetryCounter = MAX_VOLATILE_PIN_RETRIES
        //spec| Authenticator decrypts newPinEnc using above "sharedSecret" producing newPin and
        //spec| checks newPin length against minimum PIN length of 4 bytes.
        //spec| The decrypted padded newPin should be of at least 64 bytes length and authenticator
        //spec| determines actual PIN length by looking for first 0x00 byte which terminates the PIN.
        //spec| If minimum PIN length check fails, authenticator returns CTAP2_ERR_PIN_POLICY_VIOLATION error.
        val newPIN = CipherUtil.decryptWithAESCBCNoPadding(newPinEnc, secretKey, ZERO_IV)
        val sentinelPos = ArrayUtil.indexOf(newPIN, 0x00.toByte())
        if (sentinelPos < 0) {
            return AuthenticatorClientPINResponse(CtapStatusCode.CTAP2_ERR_PIN_POLICY_VIOLATION)
        }
        val trimmedNewPIN = newPIN.copyOf(sentinelPos)
        if (trimmedNewPIN.size < 4) {
            return AuthenticatorClientPINResponse(CtapStatusCode.CTAP2_ERR_PIN_POLICY_VIOLATION)
        }
        if (trimmedNewPIN.size > 63) {
            return AuthenticatorClientPINResponse(CtapStatusCode.CTAP2_ERR_PIN_POLICY_VIOLATION)
        }
        //spec| Authenticator stores LEFT(SHA-256(newPin), 16) on the device and returns CTAP2_OK.
        authenticatorPropertyStore.saveClientPIN(
            Arrays.copyOf(MessageDigestUtil.createSHA256().digest(trimmedNewPIN), 16)
        )
        return AuthenticatorClientPINResponse(CtapStatusCode.CTAP2_OK)
    }

    //spec| 5.5.7 Getting pinToken from the Authenticator
    //spec| Authenticator performs following operations upon receiving the request:
    fun getPinToken(
        platformKeyAgreementKey: COSEKey?,
        pinHashEnc: ByteArray?
    ): AuthenticatorClientPINResponse {
        //spec| If Authenticator does not receive mandatory parameters for this command,
        //spec| it returns CTAP2_ERR_MISSING_PARAMETER error.
        if (platformKeyAgreementKey == null || pinHashEnc == null) {
            return AuthenticatorClientPINResponse(CtapStatusCode.CTAP2_ERR_MISSING_PARAMETER)
        }
        //spec| If the retries counter is 0, return CTAP2_ERR_PIN_BLOCKED error.
        if (authenticatorPropertyStore.loadPINRetries() == 0u) {
            return AuthenticatorClientPINResponse(CtapStatusCode.CTAP2_ERR_PIN_BLOCKED)
        }
        if (volatilePinRetryCounter <= 0) {
            return AuthenticatorClientPINResponse(CtapStatusCode.CTAP2_ERR_PIN_AUTH_BLOCKED)
        }
        //spec| Authenticator generates "sharedSecret": SHA-256((abG).x) using private key of
        //spec| authenticatorKeyAgreementKey, "a" and public key of platformKeyAgreementKey, "bG".
        val sharedSecret = generateSharedSecret(platformKeyAgreementKey)
        //spec| Authenticator decrements the retries counter by 1.
        authenticatorPropertyStore.savePINRetries(authenticatorPropertyStore.loadPINRetries() - 1u)

        //spec| Authenticator decrypts pinHashEnc and verifies against its internal stored LEFT(SHA-256(curPin), 16).
        val secretKey: SecretKey = SecretKeySpec(sharedSecret, "AES")
        val pinHash = CipherUtil.decryptWithAESCBCNoPadding(pinHashEnc, secretKey, ZERO_IV)
        val storedPinHash =
            authenticatorPropertyStore.loadClientPIN() ?: return AuthenticatorClientPINResponse(
                CtapStatusCode.CTAP2_ERR_PIN_NOT_SET
            )
        if (!Arrays.equals(pinHash, storedPinHash)) {
            //spec| If a mismatch is detected, the authenticator performs the following operations:
            //spec| Authenticator generates a new "authenticatorKeyAgreementKey".
            //spec| Generate a new ECDH P-256 key pair called "authenticatorKeyAgreementKey" denoted by
            //spec| (a, aG), where "a" denotes the private key and "aG" denotes the public key.
            authenticatorKeyAgreementKey = ECUtil.createKeyPair()
            volatilePinRetryCounter--
            //spec| Authenticator returns errors according to following conditions:
            //spec| If the retries counter is 0, return CTAP2_ERR_PIN_BLOCKED error.
            //spec| If the authenticator sees 3 consecutive mismatches, it returns CTAP2_ERR_PIN_AUTH_BLOCKED,
            //spec| indicating that power cycling is needed for further operations. This is done so that malware
            //spec| running on the platform should not be able to block the device without user interaction.
            //spec| Else return CTAP2_ERR_PIN_INVALID error.
            return when {
                authenticatorPropertyStore.loadPINRetries() == 0u ->
                    AuthenticatorClientPINResponse(CtapStatusCode.CTAP2_ERR_PIN_BLOCKED)
                volatilePinRetryCounter <= 0 ->
                    AuthenticatorClientPINResponse(CtapStatusCode.CTAP2_ERR_PIN_AUTH_BLOCKED)
                else ->
                    AuthenticatorClientPINResponse(CtapStatusCode.CTAP2_ERR_PIN_INVALID)
            }
        }
        //spec| Authenticator sets the retries counter to 8.
        authenticatorPropertyStore.savePINRetries(MAX_PIN_RETRIES)
        volatilePinRetryCounter = MAX_VOLATILE_PIN_RETRIES
        //spec| Authenticator returns encrypted pinToken using "sharedSecret": AES256-CBC(sharedSecret, IV=0, pinToken).
        //spec| pinToken should be a multiple of 16 bytes (AES block length) without any padding or IV.
        //spec| There is no PKCS #7 padding used in this scheme.
        val pinTokenEnc = CipherUtil.encryptWithAESCBCNoPadding(pinToken, secretKey, ZERO_IV)
        val responseData =
            AuthenticatorClientPINResponseData(null, pinTokenEnc, null)
        return AuthenticatorClientPINResponse(CtapStatusCode.CTAP2_OK, responseData)
    }

    fun generateSharedSecret(platformKeyAgreementKey: COSEKey): ByteArray {
        return MessageDigestUtil.createSHA256().digest(
            KeyAgreementUtil.generateSecret(
                authenticatorKeyAgreementKey.private as ECPrivateKey,
                platformKeyAgreementKey.publicKey as ECPublicKey?
            )
        )
    }

    //spec| verify it by matching it against first 16 bytes of HMAC-SHA-256 of clientDataHash parameter
    //spec| using pinToken: HMAC-SHA-256(pinToken, clientDataHash).
    fun validatePINAuth(pinAuth: ByteArray?, clientDataHash: ByteArray?) {
        val calculatedPinAuth = MACUtil.calculateHmacSHA256(clientDataHash, pinToken, 16)
        if (!Arrays.equals(calculatedPinAuth, pinAuth)) {
            throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_PIN_AUTH_INVALID)
        }
    }

    fun resetVolatilePinRetryCounter() {
        volatilePinRetryCounter = MAX_VOLATILE_PIN_RETRIES
    }

    val isClientPINReady: Boolean
        get() = authenticatorPropertyStore.loadClientPIN() != null
    val clientPIN: ByteArray?
        get() = authenticatorPropertyStore.loadClientPIN()

}
