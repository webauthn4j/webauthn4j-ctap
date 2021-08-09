package com.webauthn4j.ctap.authenticator

import com.webauthn4j.ctap.authenticator.exception.CtapCommandExecutionException
import com.webauthn4j.ctap.authenticator.store.AuthenticatorPropertyStore
import com.webauthn4j.ctap.core.data.AuthenticatorClientPINResponse
import com.webauthn4j.ctap.core.data.AuthenticatorClientPINResponseData
import com.webauthn4j.ctap.core.data.StatusCode
import com.webauthn4j.ctap.core.util.internal.ArrayUtil
import com.webauthn4j.ctap.core.util.internal.CipherUtil
import com.webauthn4j.ctap.core.util.internal.KeyAgreementUtil
import com.webauthn4j.data.attestation.authenticator.COSEKey
import com.webauthn4j.data.attestation.authenticator.EC2COSEKey
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier
import com.webauthn4j.util.ECUtil
import com.webauthn4j.util.MACUtil
import com.webauthn4j.util.MessageDigestUtil
import java.io.Serializable
import java.nio.ByteBuffer
import java.security.SecureRandom
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.util.*
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

class ClientPINService(private val authenticatorPropertyStore: AuthenticatorPropertyStore) {

    companion object {
        const val MAX_PIN_RETRIES = 8
        const val MAX_VOLATILE_PIN_RETRIES = 3
        private val ZERO_IV = byteArrayOf(
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00
        )
        private val ECDH_ES_HKDF_256 = COSEAlgorithmIdentifier.create(-25)
    }

    private var volatilePinRetryCounter = MAX_VOLATILE_PIN_RETRIES
    var authenticatorKeyAgreementKey = ECUtil.createKeyPair() //TODO: セッションを跨いで再利用されているが大丈夫か？
    val pinToken: ByteArray = ByteArray(16)

    init {
        SecureRandom().nextBytes(pinToken)
    }

    //spec| Retries count is the number of attempts remaining before lockout. When the device is nearing authenticator lockout, the platform can optionally warn the user to be careful while entering the PIN.
    //spec| Platform performs the following operations to get retries:
    //spec| - Platform sends authenticatorClientPIN command with following parameters to the authenticator:
    //spec| -- pinProtocol: 0x01
    //spec| -- subCommand: getRetries(0x01)
    //spec| - Authenticator responds back with retries.
    fun getPinRetries(): AuthenticatorClientPINResponse {
        //spec| Retries count is the number of attempts remaining before lockout. When the device is nearing authenticator lockout, the platform can optionally warn the user to be careful while entering the PIN.
        //spec| Platform performs the following operations to get retries:
        //spec| - Platform sends authenticatorClientPIN command with following parameters to the authenticator:
        //spec| -- pinProtocol: 0x01
        //spec| -- subCommand: getRetries(0x01)
        //spec| - Authenticator responds back with retries.
        val pinRetries = authenticatorPropertyStore.loadPINRetries()
        val responseData = AuthenticatorClientPINResponseData(null, null, pinRetries.toLong())
        return AuthenticatorClientPINResponse(StatusCode.CTAP2_OK, responseData)
    }

    //spec| - Authenticator responds back with public key of authenticatorKeyAgreementKey, "aG".
    fun getKeyAgreement(): AuthenticatorClientPINResponse{

        //spec| - Authenticator responds back with public key of authenticatorKeyAgreementKey, "aG".
        val keyAgreement = EC2COSEKey.create(
            (authenticatorKeyAgreementKey.public as ECPublicKey),
            ECDH_ES_HKDF_256
        )
        val responseData = AuthenticatorClientPINResponseData(keyAgreement, null, null)
        return AuthenticatorClientPINResponse(StatusCode.CTAP2_OK, responseData)
    }

    fun setPIN(
        platformKeyAgreementKey: COSEKey?,
        pinAuth: ByteArray?,
        newPinEnc: ByteArray?
    ): AuthenticatorClientPINResponse {

        //spec| - Authenticator performs following operations upon receiving the request:
        //spec| -- If Authenticator does not receive mandatory parameters for this command, it returns CTAP2_ERR_MISSING_PARAMETER error.
        if (platformKeyAgreementKey == null || pinAuth == null || newPinEnc == null) {
            return AuthenticatorClientPINResponse(StatusCode.CTAP2_ERR_MISSING_PARAMETER)
        }
        //spec| -- If a PIN has already been set, authenticator returns CTAP2_ERR_PIN_AUTH_INVALID error.
        if (isClientPINReady) {
            return AuthenticatorClientPINResponse(StatusCode.CTAP2_ERR_PIN_AUTH_INVALID)
        }
        //spec| -- Authenticator generates "sharedSecret": SHA-256((abG).x) using private key of authenticatorKeyAgreementKey, "a" and public key of platformKeyAgreementKey, "bG".
        //spec| --- SHA-256 is done over only "x" curve point of "abG"
        //spec| --- See [RFC6090] Section 4.1 and appendix (C.2) of [SP800-56A] for more ECDH key agreement protocol details and key representation.
        val sharedSecret = generateSharedSecret(platformKeyAgreementKey)

        //spec| -- Authenticator verifies pinAuth by generating LEFT(HMAC-SHA-256(sharedSecret, newPinEnc), 16) and matching against input pinAuth parameter.
        //spec| --- If pinAuth verification fails, authenticator returns CTAP2_ERR_PIN_AUTH_INVALID error.
        val mac = MACUtil.calculateHmacSHA256(newPinEnc, sharedSecret, 16)
        if (!Arrays.equals(mac, pinAuth)) {
            return AuthenticatorClientPINResponse(StatusCode.CTAP2_ERR_PIN_AUTH_INVALID)
        }
        //spec| -- Authenticator decrypts newPinEnc using above "sharedSecret" producing newPin and checks newPin length against minimum PIN length of 4 bytes.
        //spec| --- The decrypted padded newPin should be of at least 64 bytes length and authenticator determines actual PIN length by looking for first 0x00 byte which terminates the PIN.
        //spec| --- If minimum PIN length check fails, authenticator returns CTAP2_ERR_PIN_POLICY_VIOLATION error.
        val secretKey: SecretKey = SecretKeySpec(sharedSecret, "AES")
        val newPIN = CipherUtil.decryptWithAESCBCNoPadding(newPinEnc, secretKey, ZERO_IV)
        val sentinelPos = ArrayUtil.indexOf(newPIN, 0x00.toByte())
        if (sentinelPos < 0) {
            return AuthenticatorClientPINResponse(StatusCode.CTAP2_ERR_PIN_POLICY_VIOLATION)
        }
        val trimmedNewPIN = newPIN.copyOf(sentinelPos)
        if (trimmedNewPIN.size < 4) {
            return AuthenticatorClientPINResponse(StatusCode.CTAP2_ERR_PIN_POLICY_VIOLATION)
        }
        if (trimmedNewPIN.size > 63) {
            return AuthenticatorClientPINResponse(StatusCode.CTAP2_ERR_PIN_POLICY_VIOLATION)
        }
        //spec| --- Authenticator may have additional constraints for PIN policy. The current spec only enforces minimum length of 4 bytes.
        //spec| -- Authenticator stores LEFT(SHA-256(newPin), 16) on the device, sets the retries counter to 8, and returns CTAP2_OK.
        authenticatorPropertyStore.saveClientPIN(trimmedNewPIN)
        val pinRetries = MAX_PIN_RETRIES
        authenticatorPropertyStore.savePINRetries(pinRetries)
        val responseData = AuthenticatorClientPINResponseData(null, null, pinRetries.toLong())
        return AuthenticatorClientPINResponse(StatusCode.CTAP2_OK, responseData)
    }

    fun changePIN(
        platformKeyAgreementKey: COSEKey?,
        pinAuth: ByteArray?,
        newPinEnc: ByteArray?,
        pinHashEnc: ByteArray?
    ): AuthenticatorClientPINResponse {
        //spec| - Authenticator performs following operations upon receiving the request:
        //spec| -- If Authenticator does not receive mandatory parameters for this command, it returns CTAP2_ERR_MISSING_PARAMETER error.
        if (platformKeyAgreementKey == null || pinAuth == null || newPinEnc == null || pinHashEnc == null) {
            return AuthenticatorClientPINResponse(StatusCode.CTAP2_ERR_MISSING_PARAMETER)
        }
        //spec| -- If the retries counter is 0, return CTAP2_ERR_PIN_BLOCKED error.
        if (authenticatorPropertyStore.loadPINRetries() == 0) {
            return AuthenticatorClientPINResponse(StatusCode.CTAP2_ERR_PIN_BLOCKED)
        } else if (volatilePinRetryCounter == 0) {
            return AuthenticatorClientPINResponse(StatusCode.CTAP2_ERR_PIN_AUTH_BLOCKED)
        }
        //spec| -- Authenticator generates "sharedSecret": SHA-256((abG).x) using private key of authenticatorKeyAgreementKey, "a" and public key of platformKeyAgreementKey, "bG".
        //spec| --- SHA-256 is done over only "x" curve point of "abG"
        //spec| ---- See [RFC6090] Section 4.1 and appendix (C.2) of [SP800-56A] for more ECDH key agreement protocol details and key representation.
        val sharedSecret = generateSharedSecret(platformKeyAgreementKey)
        //spec| -- Authenticator verifies pinAuth by generating LEFT(HMAC-SHA-256(sharedSecret, newPinEnc || pinHashEnc), 16) and matching against input pinAuth parameter.
        //spec| --- If pinAuth verification fails, authenticator returns CTAP2_ERR_PIN_AUTH_INVALID error.
        val joined =
            ByteBuffer.allocate(newPinEnc.size + pinHashEnc.size).put(newPinEnc).put(pinHashEnc)
                .array()
        val mac = MACUtil.calculateHmacSHA256(joined, sharedSecret, 16)
        if (!Arrays.equals(mac, pinAuth)) {
            return AuthenticatorClientPINResponse(StatusCode.CTAP2_ERR_PIN_AUTH_INVALID)
        }
        //spec| -- Authenticator decrements the retries counter by 1.
        authenticatorPropertyStore.savePINRetries(authenticatorPropertyStore.loadPINRetries() - 1)
        if (volatilePinRetryCounter > 0) {
            volatilePinRetryCounter--
        }


        //spec| -- Authenticator decrypts pinHashEnc and verifies against its internal stored LEFT(SHA-256(curPin), 16).
        val secretKey: SecretKey = SecretKeySpec(sharedSecret, "AES")
        val pinHash = CipherUtil.decryptWithAESCBCNoPadding(pinHashEnc, secretKey, ZERO_IV)
        val clientPIN = authenticatorPropertyStore.loadClientPIN()
            ?: return AuthenticatorClientPINResponse(StatusCode.CTAP2_ERR_PIN_NOT_SET)
        //
        //
        //
        // !!!NOT in spec!!! //TODO: ask spec author
        val currentPINHash = Arrays.copyOf(MessageDigestUtil.createSHA256().digest(clientPIN), 16)
        if (!Arrays.equals(pinHash, currentPINHash)) {
            //spec| --- If a mismatch is detected, the authenticator performs the following operations:
            //spec| ---- Authenticator generates a new "authenticatorKeyAgreementKey".
            //spec| ----- Generate a new ECDH P-256 key pair called "authenticatorKeyAgreementKey" denoted by (a, aG), where "a" denotes the private key and "aG" denotes the public key.
            //spec| ------ See [RFC6090] Section 4.1 and [SP800-56A] for more ECDH key agreement protocol details.
            authenticatorKeyAgreementKey = ECUtil.createKeyPair()
            //spec| ---- Authenticator returns errors according to following conditions:
            //spec| ----- If the retries counter is 0, return CTAP2_ERR_PIN_BLOCKED error.
            // This step is already done above.
            //spec| ----- If the authenticator sees 3 consecutive mismatches, it returns CTAP2_ERR_PIN_AUTH_BLOCKED,
            //spec|       indicating that power cycling is needed for further operations.
            //spec|       This is done so that malware running on the platform should not be able to block the device without user interaction.
            // This step is already done above.
            //spec| ----- Else return CTAP2_ERR_PIN_INVALID error.
            return AuthenticatorClientPINResponse(StatusCode.CTAP2_ERR_PIN_INVALID)
        }
        //spec| --- Authenticator sets the retries counter to 8.
        authenticatorPropertyStore.savePINRetries(MAX_PIN_RETRIES)
        //spec| --- Authenticator decrypts newPinEnc using above "sharedSecret" producing newPin and checks newPin length against minimum PIN length of 4 bytes.
        //spec| ---- The decrypted padded newPin should be of at least 64 bytes length and authenticator determines actual PIN length by looking for first 0x00 byte which terminates the PIN.
        //spec| ---- If minimum PIN length check fails, authenticator returns CTAP2_ERR_PIN_POLICY_VIOLATION error.
        //spec| ---- Authenticator may have additional constraints for PIN policy. The current spec only enforces minimum length of 4 bytes.
        val newPIN = CipherUtil.decryptWithAESCBCNoPadding(newPinEnc, secretKey, ZERO_IV)
        val sentinelPos = ArrayUtil.indexOf(newPIN, 0x00.toByte())
        if (sentinelPos < 0) {
            return AuthenticatorClientPINResponse(StatusCode.CTAP2_ERR_PIN_POLICY_VIOLATION)
        }
        val trimmedNewPIN = newPIN.copyOf(sentinelPos)
        if (trimmedNewPIN.size < 4) {
            return AuthenticatorClientPINResponse(StatusCode.CTAP2_ERR_PIN_POLICY_VIOLATION)
        }
        if (trimmedNewPIN.size > 63) {
            return AuthenticatorClientPINResponse(StatusCode.CTAP2_ERR_PIN_POLICY_VIOLATION)
        }
        //spec| --- Authenticator stores LEFT(SHA-256(newPin), 16) on the device and returns CTAP2_OK.
        authenticatorPropertyStore.saveClientPIN(trimmedNewPIN) // clientPIN is not trimmedPIN. This is intended.
        val pinRetires = authenticatorPropertyStore.loadPINRetries()
        val responseData = AuthenticatorClientPINResponseData(null, null, pinRetires.toLong())
        return AuthenticatorClientPINResponse(StatusCode.CTAP2_OK, responseData)
    }

    fun getPinToken(
        platformKeyAgreementKey: COSEKey?,
        pinHashEnc: ByteArray?
    ): AuthenticatorClientPINResponse {
        //spec| - Authenticator performs following operations upon receiving the request:
        //spec| -- If Authenticator does not receive mandatory parameters for this command, it returns CTAP2_ERR_MISSING_PARAMETER error.
        if (platformKeyAgreementKey == null || pinHashEnc == null) {
            return AuthenticatorClientPINResponse(StatusCode.CTAP2_ERR_MISSING_PARAMETER)
        }
        //spec| -- If the retries counter is 0, return CTAP2_ERR_PIN_BLOCKED error.
        if (authenticatorPropertyStore.loadPINRetries() == 0) {
            return AuthenticatorClientPINResponse(StatusCode.CTAP2_ERR_PIN_BLOCKED)
        }
        //spec| -- Authenticator generates "sharedSecret": SHA-256((abG).x) using private key of authenticatorKeyAgreementKey, "a" and public key of platformKeyAgreementKey, "bG".
        //spec| --- SHA-256 is done over only "x" curve point of "abG"
        //spec| --- See [RFC6090] Section 4.1 and appendix (C.2) of [SP800-56A] for more ECDH key agreement protocol details and key representation.
        val sharedSecret = generateSharedSecret(platformKeyAgreementKey)
        //spec| -- Authenticator decrements the retries counter by 1.
        authenticatorPropertyStore.savePINRetries(authenticatorPropertyStore.loadPINRetries() - 1)
        volatilePinRetryCounter--

        //spec| -- Authenticator decrypts pinHashEnc and verifies against its internal stored LEFT(SHA-256(curPin), 16).
        val secretKey: SecretKey = SecretKeySpec(sharedSecret, "AES")
        val pinHash = CipherUtil.decryptWithAESCBCNoPadding(pinHashEnc, secretKey, ZERO_IV)
        val clientPIN =
            authenticatorPropertyStore.loadClientPIN() ?: return AuthenticatorClientPINResponse(
                StatusCode.CTAP2_ERR_PIN_NOT_SET
            )
        val currentPINHash = Arrays.copyOf(MessageDigestUtil.createSHA256().digest(clientPIN), 16)
        if (!Arrays.equals(pinHash, currentPINHash)) {
            //spec| --- If a mismatch is detected, the authenticator performs the following operations:
            //spec| ---- Authenticator generates a new "authenticatorKeyAgreementKey".
            //spec| ----- Generate a new ECDH P-256 key pair called "authenticatorKeyAgreementKey" denoted by (a, aG), where "a" denotes the private key and "aG" denotes the public key.
            //spec| ------ See [RFC6090] Section 4.1 and [SP800-56A] for more ECDH key agreement protocol details.
            authenticatorKeyAgreementKey = ECUtil.createKeyPair()
            //spec| ---- Authenticator returns errors according to following conditions:
            //spec| ----- If the retries counter is 0, return CTAP2_ERR_PIN_BLOCKED error.
            return when {
                authenticatorPropertyStore.loadPINRetries() == 0 -> AuthenticatorClientPINResponse(
                    StatusCode.CTAP2_ERR_PIN_BLOCKED
                )
                volatilePinRetryCounter == 0 -> AuthenticatorClientPINResponse(StatusCode.CTAP2_ERR_PIN_AUTH_BLOCKED)
                else -> AuthenticatorClientPINResponse(StatusCode.CTAP2_ERR_PIN_INVALID)
            }
        }
        //spec| -- Authenticator sets the retries counter to 8.
        authenticatorPropertyStore.savePINRetries(MAX_PIN_RETRIES)
        //spec| -- Authenticator returns encrypted pinToken using "sharedSecret": AES256-CBC(sharedSecret, IV=0, pinToken).
        //spec| --- pinToken should be a multiple of 16 bytes (AES block length) without any padding or IV. There is no PKCS #7 padding used in this scheme.
        val pinTokenEnc = CipherUtil.encryptWithAESCBCNoPadding(pinToken, secretKey, ZERO_IV)
        val pinRetries = authenticatorPropertyStore.loadPINRetries()
        val responseData =
            AuthenticatorClientPINResponseData(null, pinTokenEnc, pinRetries.toLong())
        return AuthenticatorClientPINResponse(StatusCode.CTAP2_OK, responseData)
    }

    fun generateSharedSecret(platformKeyAgreementKey: COSEKey): ByteArray{
        return MessageDigestUtil.createSHA256().digest(
            KeyAgreementUtil.generateSecret(
                authenticatorKeyAgreementKey.private as ECPrivateKey,
                platformKeyAgreementKey.publicKey as ECPublicKey?
            )
        )
    }

    fun validatePINAuth(pinAuth: ByteArray?, clientDataHash: ByteArray?) {
        val calculatedPinAuth = MACUtil.calculateHmacSHA256(clientDataHash, pinToken, 16)
        if (!Arrays.equals(calculatedPinAuth, pinAuth)) {
            throw CtapCommandExecutionException(StatusCode.CTAP2_ERR_PIN_AUTH_INVALID)
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