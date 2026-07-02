package com.webauthn4j.ctap.authenticator

import com.webauthn4j.ctap.authenticator.execution.CtapCommandExecutionException
import com.webauthn4j.ctap.authenticator.store.AuthenticatorPropertyStore
import com.webauthn4j.ctap.core.data.AuthenticatorClientPINResponse
import com.webauthn4j.ctap.core.data.AuthenticatorClientPINResponseData
import com.webauthn4j.ctap.core.data.CtapStatusCode
import com.webauthn4j.data.PinProtocolVersion
import com.webauthn4j.ctap.core.util.internal.ArrayUtil
import com.webauthn4j.data.attestation.authenticator.COSEKey
import com.webauthn4j.util.MessageDigestUtil
import java.nio.ByteBuffer
import java.util.Arrays

/**
 * Service handling authenticatorClientPIN command operations.
 *
 * Supports multiple PIN/UV Auth Protocol versions by delegating cryptographic operations
 * to [PinUvAuthProtocol] instances.
 *
 * @see <a href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorClientPIN">6.5. authenticatorClientPIN</a>
 */
class PinUvAuthService(
    private val authenticatorPropertyStore: AuthenticatorPropertyStore,
    private val protocols: List<PinUvAuthProtocol> = listOf(PinUvAuthProtocolV1())
) {

    companion object {
        const val MAX_PIN_RETRIES: UInt = 8u
        const val MAX_VOLATILE_PIN_RETRIES = 3
    }

    private var volatilePinRetryCounter = MAX_VOLATILE_PIN_RETRIES

    private val protocolMap: Map<PinProtocolVersion, PinUvAuthProtocol> = protocols.associateBy { it.version }

    fun getProtocol(pinProtocol: PinProtocolVersion): PinUvAuthProtocol {
        return protocolMap[pinProtocol]
            ?: throw CtapCommandExecutionException(CtapStatusCode.CTAP1_ERR_INVALID_PARAMETER)
    }

    //spec| 6.5.5.2 Platform getting PIN retries from Authenticator
    //spec| Authenticator responds back with pinRetries and, optionally, powerCycleState.
    fun getPinRetries(): AuthenticatorClientPINResponse {
        val pinRetries = authenticatorPropertyStore.loadPINRetries()
        val responseData = AuthenticatorClientPINResponseData(null, null, pinRetries)
        return AuthenticatorClientPINResponse(CtapStatusCode.CTAP2_OK, responseData)
    }

    //spec| 6.5.5.4 Obtaining the Shared Secret
    //spec| Otherwise the authenticator sends a response with the following parameters:
    //spec| keyAgreement: the result of calling getPublicKey for the selected pinUvAuthProtocol.
    fun getKeyAgreement(pinProtocol: PinProtocolVersion): AuthenticatorClientPINResponse {
        val protocol = getProtocol(pinProtocol)
        val keyAgreement = protocol.getPublicKey()
        val responseData = AuthenticatorClientPINResponseData(keyAgreement, null, null)
        return AuthenticatorClientPINResponse(CtapStatusCode.CTAP2_OK, responseData)
    }

    //spec| 6.5.5.5 Setting a New PIN
    //spec| Authenticator performs following operations upon receiving the request:
    fun setPIN(
        pinProtocol: PinProtocolVersion,
        platformKeyAgreementKey: COSEKey?,
        pinAuth: ByteArray?,
        newPinEnc: ByteArray?
    ): AuthenticatorClientPINResponse {

        //spec| If the authenticator does not receive mandatory parameters for this command,
        //spec| it returns CTAP2_ERR_MISSING_PARAMETER error.
        if (platformKeyAgreementKey == null || pinAuth == null || newPinEnc == null) {
            return AuthenticatorClientPINResponse(CtapStatusCode.CTAP2_ERR_MISSING_PARAMETER)
        }
        //spec| If a PIN has already been set, authenticator returns CTAP2_ERR_PIN_AUTH_INVALID error.
        if (isClientPINReady) {
            return AuthenticatorClientPINResponse(CtapStatusCode.CTAP2_ERR_PIN_AUTH_INVALID)
        }

        val protocol = getProtocol(pinProtocol)

        //spec| The authenticator calls decapsulate on the provided platform key-agreement key
        //spec| to obtain the shared secret. If an error results, it returns CTAP1_ERR_INVALID_PARAMETER.
        val sharedSecret = protocol.decapsulate(platformKeyAgreementKey)

        //spec| The authenticator calls verify(shared secret, newPinEnc, pinUvAuthParam)
        //spec| If an error results, it returns CTAP2_ERR_PIN_AUTH_INVALID.
        if (!protocol.verify(sharedSecret, newPinEnc, pinAuth)) {
            return AuthenticatorClientPINResponse(CtapStatusCode.CTAP2_ERR_PIN_AUTH_INVALID)
        }
        //spec| The authenticator calls decrypt(shared secret, newPinEnc) to produce paddedNewPin.
        //spec| If an error results, it returns CTAP2_ERR_PIN_AUTH_INVALID.
        val newPIN = protocol.decrypt(sharedSecret, newPinEnc)
        //spec| The authenticator drops all trailing 0x00 bytes from paddedNewPin to produce newPin.
        val sentinelPos = newPIN.indexOf(0x00)
        val trimmedNewPIN: ByteArray = when {
            (sentinelPos < 0) -> newPIN
            else -> newPIN.copyOf(sentinelPos)
        }
        //spec| The authenticator checks the length of newPin against the current minimum PIN length,
        //spec| returning CTAP2_ERR_PIN_POLICY_VIOLATION if it is too short.
        if (trimmedNewPIN.size < 4) {
            return AuthenticatorClientPINResponse(CtapStatusCode.CTAP2_ERR_PIN_POLICY_VIOLATION)
        }
        if (trimmedNewPIN.size > 63) {
            return AuthenticatorClientPINResponse(CtapStatusCode.CTAP2_ERR_PIN_POLICY_VIOLATION)
        }
        //spec| The authenticator stores LEFT(SHA-256(newPin), 16) internally as CurrentStoredPIN,
        //spec| sets the pinRetries counter to maximum count, and returns CTAP2_OK.
        authenticatorPropertyStore.saveClientPIN(
            Arrays.copyOf(MessageDigestUtil.createSHA256().digest(trimmedNewPIN), 16)
        )
        authenticatorPropertyStore.savePINRetries(MAX_PIN_RETRIES)
        return AuthenticatorClientPINResponse(CtapStatusCode.CTAP2_OK)
    }

    //spec| 6.5.5.6 Changing existing PIN
    //spec| Authenticator performs following operations upon receiving the request:
    fun changePIN(
        pinProtocol: PinProtocolVersion,
        platformKeyAgreementKey: COSEKey?,
        pinAuth: ByteArray?,
        newPinEnc: ByteArray?,
        pinHashEnc: ByteArray?
    ): AuthenticatorClientPINResponse {
        //spec| If the authenticator does not receive mandatory parameters for this command,
        //spec| it returns CTAP2_ERR_MISSING_PARAMETER error.
        if (platformKeyAgreementKey == null || pinAuth == null || newPinEnc == null || pinHashEnc == null) {
            return AuthenticatorClientPINResponse(CtapStatusCode.CTAP2_ERR_MISSING_PARAMETER)
        }
        //spec| If the pinRetries counter is 0, return CTAP2_ERR_PIN_BLOCKED error.
        if (authenticatorPropertyStore.loadPINRetries() == 0u) {
            return AuthenticatorClientPINResponse(CtapStatusCode.CTAP2_ERR_PIN_BLOCKED)
        }

        val protocol = getProtocol(pinProtocol)

        //spec| The authenticator calls decapsulate on the provided platform key-agreement key
        //spec| to obtain the shared secret. If an error results, it returns CTAP1_ERR_INVALID_PARAMETER.
        val sharedSecret = protocol.decapsulate(platformKeyAgreementKey)
        //spec| The authenticator calls verify(shared secret, newPinEnc || pinHashEnc, pinUvAuthParam)
        //spec| If an error results, it returns CTAP2_ERR_PIN_AUTH_INVALID.
        val joined =
            ByteBuffer.allocate(newPinEnc.size + pinHashEnc.size).put(newPinEnc).put(pinHashEnc)
                .array()
        if (!protocol.verify(sharedSecret, joined, pinAuth)) {
            return AuthenticatorClientPINResponse(CtapStatusCode.CTAP2_ERR_PIN_AUTH_INVALID)
        }
        //spec| The authenticator decrements the pinRetries counter by 1.
        authenticatorPropertyStore.savePINRetries(authenticatorPropertyStore.loadPINRetries() - 1u)

        //spec| The authenticator decrypts pinHashEnc using decrypt(shared secret, pinHashEnc)
        //spec| and verifies against its internal stored LEFT(SHA-256(curPin), 16).
        val pinHash = protocol.decrypt(sharedSecret, pinHashEnc)
        val storedPinHash =
            authenticatorPropertyStore.loadClientPIN() ?: return AuthenticatorClientPINResponse(
                CtapStatusCode.CTAP2_ERR_PIN_NOT_SET
            )

        if (!Arrays.equals(pinHash, storedPinHash)) {
            //spec| If an error results, or a mismatch is detected, the authenticator performs the following operations:
            //spec| Calls regenerate for the selected pinUvAuthProtocol.
            protocol.regenerate()
            volatilePinRetryCounter--
            //spec| The authenticator returns errors according to following conditions:
            //spec| If the pinRetries counter is 0, return CTAP2_ERR_PIN_BLOCKED error.
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
        //spec| The authenticator sets the pinRetries counter to maximum value.
        authenticatorPropertyStore.savePINRetries(MAX_PIN_RETRIES)
        volatilePinRetryCounter = MAX_VOLATILE_PIN_RETRIES
        //spec| The authenticator calls decrypt(shared secret, newPinEnc) to produce paddedNewPin.
        //spec| If an error results, it returns CTAP2_ERR_PIN_AUTH_INVALID.
        //spec| The authenticator drops all trailing 0x00 bytes from paddedNewPin to produce newPin.
        //spec| The authenticator checks the length of newPin against the current minimum PIN length,
        //spec| returning CTAP2_ERR_PIN_POLICY_VIOLATION if it is too short.
        val newPIN = protocol.decrypt(sharedSecret, newPinEnc)
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
        //spec| The authenticator stores LEFT(SHA-256(newPin), 16) internally as the new value of CurrentStoredPIN.
        //spec| The authenticator returns CTAP2_OK.
        authenticatorPropertyStore.saveClientPIN(
            Arrays.copyOf(MessageDigestUtil.createSHA256().digest(trimmedNewPIN), 16)
        )
        return AuthenticatorClientPINResponse(CtapStatusCode.CTAP2_OK)
    }

    //spec| 6.5.5.7.1 Getting pinUvAuthToken using getPinToken (superseded)
    //spec| Authenticator performs following operations upon receiving the request:
    fun getPinToken(
        pinProtocol: PinProtocolVersion,
        platformKeyAgreementKey: COSEKey?,
        pinHashEnc: ByteArray?
    ): AuthenticatorClientPINResponse {
        //spec| If the authenticator does not receive mandatory parameters for this command,
        //spec| it returns CTAP2_ERR_MISSING_PARAMETER error.
        if (platformKeyAgreementKey == null || pinHashEnc == null) {
            return AuthenticatorClientPINResponse(CtapStatusCode.CTAP2_ERR_MISSING_PARAMETER)
        }
        //spec| If the pinRetries counter is 0, return CTAP2_ERR_PIN_BLOCKED error.
        if (authenticatorPropertyStore.loadPINRetries() == 0u) {
            return AuthenticatorClientPINResponse(CtapStatusCode.CTAP2_ERR_PIN_BLOCKED)
        }
        if (volatilePinRetryCounter <= 0) {
            return AuthenticatorClientPINResponse(CtapStatusCode.CTAP2_ERR_PIN_AUTH_BLOCKED)
        }

        val protocol = getProtocol(pinProtocol)

        //spec| The authenticator calls decapsulate on the provided platform key-agreement key
        //spec| to obtain the shared secret. If an error results, it returns CTAP1_ERR_INVALID_PARAMETER.
        val sharedSecret = protocol.decapsulate(platformKeyAgreementKey)
        //spec| The authenticator decrements the pinRetries counter by 1.
        authenticatorPropertyStore.savePINRetries(authenticatorPropertyStore.loadPINRetries() - 1u)

        //spec| The authenticator decrypts pinHashEnc using decrypt and verifies against its
        //spec| internally stored CurrentStoredPIN.
        val pinHash = protocol.decrypt(sharedSecret, pinHashEnc)
        val storedPinHash =
            authenticatorPropertyStore.loadClientPIN() ?: return AuthenticatorClientPINResponse(
                CtapStatusCode.CTAP2_ERR_PIN_NOT_SET
            )
        if (!Arrays.equals(pinHash, storedPinHash)) {
            //spec| If an error results, or a mismatch is detected, the authenticator performs the following operations:
            //spec| Calls regenerate for the selected pinUvAuthProtocol.
            protocol.regenerate()
            volatilePinRetryCounter--
            //spec| The authenticator returns errors according to following conditions:
            //spec| If the pinRetries counter is 0, return CTAP2_ERR_PIN_BLOCKED error.
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
        //spec| The authenticator sets the pinRetries counter to maximum value.
        authenticatorPropertyStore.savePINRetries(MAX_PIN_RETRIES)
        volatilePinRetryCounter = MAX_VOLATILE_PIN_RETRIES
        //spec| The authenticator returns the encrypted pinUvAuthToken for the specified pinUvAuthProtocol,
        //spec| i.e. encrypt(shared secret, pinUvAuthToken).
        val pinTokenEnc = protocol.encrypt(sharedSecret, protocol.pinUvAuthToken)
        val responseData =
            AuthenticatorClientPINResponseData(null, pinTokenEnc, null)
        return AuthenticatorClientPINResponse(CtapStatusCode.CTAP2_OK, responseData)
    }

    //spec| Call verify(pinUvAuthToken, clientDataHash, pinUvAuthParam).
    //spec| If the verification returns error, then end the operation by returning CTAP2_ERR_PIN_AUTH_INVALID error.
    fun verifyPinUvAuthParam(pinAuth: ByteArray?, clientDataHash: ByteArray?) {
        if (pinAuth == null || clientDataHash == null) {
            throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_PIN_AUTH_INVALID)
        }
        // Try verification against all protocols' pinUvAuthTokens
        for (protocol in protocols) {
            val calculatedPinAuth = protocol.authenticate(
                protocol.pinUvAuthToken, clientDataHash
            )
            if (Arrays.equals(calculatedPinAuth, pinAuth)) {
                return
            }
        }
        throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_PIN_AUTH_INVALID)
    }

    val isClientPINReady: Boolean
        get() = authenticatorPropertyStore.loadClientPIN() != null
    val clientPIN: ByteArray?
        get() = authenticatorPropertyStore.loadClientPIN()

}
