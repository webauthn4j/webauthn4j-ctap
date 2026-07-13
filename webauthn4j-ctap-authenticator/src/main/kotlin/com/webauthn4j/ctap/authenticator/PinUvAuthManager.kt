package com.webauthn4j.ctap.authenticator
import com.webauthn4j.ctap.core.data.PinUvAuthTokenPermission
import com.webauthn4j.ctap.core.data.PinUvAuthTokenPermissions

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
 * Implementation of the authenticatorClientPIN (0x06) command subcommands
 * defined in CTAP 2.3 §6.5.5.
 *
 * Each public method corresponds to a subcommand (getPINRetries, getKeyAgreement,
 * setPIN, changePIN, getPinToken, getPinUvAuthTokenUsingPinWithPermissions,
 * getPinUvAuthTokenUsingUvWithPermissions, getUVRetries).
 *
 * Holds volatile state (e.g. PIN retry counters) that resets on power cycle,
 * as required by the spec.
 *
 * @see <a href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorClientPIN">6.5. authenticatorClientPIN</a>
 */
class PinUvAuthManager(
    private val authenticatorPropertyStore: AuthenticatorPropertyStore,
    val pinUvAuthProtocols: List<PinUvAuthProtocol> = listOf(PinUvAuthProtocolV1())
) {

    companion object {
        const val MAX_PIN_RETRIES: UInt = 8u
        const val MAX_VOLATILE_PIN_RETRIES = 3
        const val MAX_UV_RETRIES: UInt = 3u
        // §6.4 minPINLength (0x0D): default minimum PIN length in Unicode code points
        const val DEFAULT_MIN_PIN_LENGTH = 4
    }

    // §6.4 minPINLength (0x0D)
    // TODO: update via authenticatorConfig setMinPINLength subcommand when implemented
    var minPINLength: Int = DEFAULT_MIN_PIN_LENGTH
        private set

    private var volatilePinRetryCounter = MAX_VOLATILE_PIN_RETRIES

    //spec| 6.5.5.2. Platform getting PIN retries from Authenticator
    //spec| PIN retries count is the number of PIN attempts remaining before PIN is disabled on the device.
    //spec| When the PIN retries count nears zero,
    //spec| the platform can optionally warn the user to be careful while entering the PIN.
    //spec| Platform performs the following operations to get pinRetries:
    //spec|   1. Platform sends authenticatorClientPIN command
    //spec|      with following parameters to the authenticator:
    //spec|        subCommand: getPINRetries(0x01)
    //spec|   2. Authenticator responds back with pinRetries and, optionally,
    //spec|      powerCycleState.
    // @see <a href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#gettingPINRetries">§6.5.5.2</a>
    fun getPinRetries(): AuthenticatorClientPINResponse {
        //spec| Step 2: Authenticator responds back with pinRetries and, optionally, powerCycleState.
        val pinRetries = authenticatorPropertyStore.loadPINRetries()
        val powerCycleState = if (volatilePinRetryCounter <= 0) true else null
        val responseData = AuthenticatorClientPINResponseData(null, null, pinRetries, powerCycleState, null)
        return AuthenticatorClientPINResponse(CtapStatusCode.CTAP2_OK, responseData)
    }

    //spec| 6.5.5.4. Obtaining the Shared Secret
    //spec| subCommand: getKeyAgreement (0x02)
    //spec| Platforms obtain a shared secret for each transaction. The authenticator does not have to keep a list of
    //spec| sharedSecrets for all active sessions. If there are subsequent authenticatorClientPIN transactions, a new
    //spec| sharedSecret is generated every time.
    //spec| Platform performs the following operations to arrive at the sharedSecret:
    //spec|   1. The platform selects a mutually supported PIN/UV auth protocol by considering the list of protocols
    //spec|      supported by the authenticator, as reported in the pinUvAuthProtocols member of the authenticatorGetInfo
    //spec|      response. If there are multiple mutually supported protocols, and the platform has no preference, it SHOULD
    //spec|      select the one listed first in pinUvAuthProtocols.
    //spec|   2. The platform sends authenticatorClientPIN command
    //spec|      with following parameters to the authenticator:
    //spec|      - pinUvAuthProtocol: as chosen above
    //spec|      - subCommand: getKeyAgreement(0x02)
    //spec|   3. If the authenticator does not receive mandatory parameters for this subcommand, end the operation by
    //spec|      returning CTAP2_ERR_MISSING_PARAMETER.
    //spec|   4. If the authenticator does not support the selected pinUvAuthProtocol, it returns
    //spec|      CTAP1_ERR_INVALID_PARAMETER.
    //spec|   5. Otherwise the authenticator sends a response with the following parameters:
    //spec|      - keyAgreement: the result of calling getPublicKey for the selected pinUvAuthProtocol.
    //spec|   6. The platform calls encapsulate with the public key that the authenticator returned in order to generate
    //spec|      the platform key-agreement key and the shared secret.
    // @see <a href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#gettingSharedSecret">§6.5.5.4</a>
    fun getKeyAgreement(pinProtocol: PinProtocolVersion): AuthenticatorClientPINResponse {
        //spec| Step 3: If the authenticator does not receive mandatory parameters for this subcommand,
        //spec| end the operation by returning CTAP2_ERR_MISSING_PARAMETER.
        // (pinProtocol is non-null by Kotlin type system; validated at deserialization layer)
        //spec| Step 4: If the authenticator does not support the selected pinUvAuthProtocol,
        //spec| it returns CTAP1_ERR_INVALID_PARAMETER.
        val protocol = getProtocol(pinProtocol)
        //spec| Step 5: Otherwise the authenticator sends a response with the following parameters:
        //spec| keyAgreement: the result of calling getPublicKey for the selected pinUvAuthProtocol.
        val keyAgreement = protocol.getPublicKey()
        val responseData = AuthenticatorClientPINResponseData(keyAgreement, null, null)
        return AuthenticatorClientPINResponse(CtapStatusCode.CTAP2_OK, responseData)
    }

    //spec| 6.5.5.5. Setting a New PIN
    //spec| subCommand: setPIN (0x03)
    //spec| The following operations are performed to set up a new PIN:
    //spec| The platform collects the new PIN (newPinUnicode) from the user as Unicode characters in Normalization
    //spec| Form C. The platform obtains the shared secret from the authenticator and sends the authenticatorClientPIN
    //spec| command with setPIN(0x03) subCommand.
    //spec| Authenticator performs following operations upon receiving the request:
    //spec|   1. If the authenticator does not receive mandatory parameters for this command,
    //spec|      it returns CTAP2_ERR_MISSING_PARAMETER error.
    //spec|   2. If pinUvAuthProtocol is not supported, return CTAP1_ERR_INVALID_PARAMETER.
    //spec|   3. If a PIN has already been set, authenticator returns CTAP2_ERR_PIN_AUTH_INVALID error.
    //spec|   4. The authenticator calls decapsulate on the provided platform key-agreement key to obtain the shared
    //spec|      secret. If an error results, it returns CTAP1_ERR_INVALID_PARAMETER.
    //spec|   5. The authenticator calls verify(shared secret, newPinEnc, pinUvAuthParam)
    //spec|      5.1. If an error results, it returns CTAP2_ERR_PIN_AUTH_INVALID.
    //spec|   6. The authenticator calls decrypt(shared secret, newPinEnc) to produce paddedNewPin. If an error results,
    //spec|      it returns CTAP2_ERR_PIN_AUTH_INVALID.
    //spec|   7. If paddedNewPin is NOT 64 bytes long, it returns CTAP1_ERR_INVALID_PARAMETER.
    //spec|   8. The authenticator drops all trailing 0x00 bytes from paddedNewPin to produce newPin.
    //spec|   9. The authenticator checks the length of newPin against the current minimum PIN length, returning
    //spec|      CTAP2_ERR_PIN_POLICY_VIOLATION if it is too short.
    //spec|   10. An authenticator MAY impose arbitrary, additional constraints on PINs. If newPin fails to satisfy such
    //spec|       additional constraints, the authenticator returns CTAP2_ERR_PIN_POLICY_VIOLATION.
    //spec|   11. The authenticator remembers newPin length internally as PINCodePointLength.
    //spec|   12. The authenticator stores LEFT(SHA-256(newPin), 16) internally as CurrentStoredPIN,
    //spec|       sets the pinRetries counter to maximum count, and returns CTAP2_OK.
    // @see <a href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#settingNewPin">§6.5.5.5</a>
    fun setPIN(
        pinProtocol: PinProtocolVersion,
        platformKeyAgreementKey: COSEKey?,
        pinAuth: ByteArray?,
        newPinEnc: ByteArray?
    ): AuthenticatorClientPINResponse {

        //spec| Step 1: If the authenticator does not receive mandatory parameters for this command,
        //spec| it returns CTAP2_ERR_MISSING_PARAMETER error.
        if (platformKeyAgreementKey == null || pinAuth == null || newPinEnc == null) {
            return AuthenticatorClientPINResponse(CtapStatusCode.CTAP2_ERR_MISSING_PARAMETER)
        }
        //spec| Step 2: If pinUvAuthProtocol is not supported, return CTAP1_ERR_INVALID_PARAMETER.
        val protocol = getProtocol(pinProtocol)
        //spec| Step 3: If a PIN has already been set, authenticator returns CTAP2_ERR_PIN_AUTH_INVALID error.
        if (authenticatorPropertyStore.loadClientPIN() != null) {
            return AuthenticatorClientPINResponse(CtapStatusCode.CTAP2_ERR_PIN_AUTH_INVALID)
        }

        //spec| Step 4: The authenticator calls decapsulate on the provided platform key-agreement key
        //spec| to obtain the shared secret. If an error results, it returns CTAP1_ERR_INVALID_PARAMETER.
        val sharedSecret = protocol.decapsulate(platformKeyAgreementKey)

        //spec| Step 5: The authenticator calls verify(shared secret, newPinEnc, pinUvAuthParam)
        //spec| If an error results, it returns CTAP2_ERR_PIN_AUTH_INVALID.
        if (!protocol.verify(sharedSecret, newPinEnc, pinAuth)) {
            return AuthenticatorClientPINResponse(CtapStatusCode.CTAP2_ERR_PIN_AUTH_INVALID)
        }
        //spec| Step 6: The authenticator calls decrypt(shared secret, newPinEnc) to produce paddedNewPin.
        //spec| If an error results, it returns CTAP2_ERR_PIN_AUTH_INVALID.
        val newPIN = protocol.decrypt(sharedSecret, newPinEnc)
        //spec| Step 7: If paddedNewPin is NOT 64 bytes long, it returns CTAP1_ERR_INVALID_PARAMETER.
        if (newPIN.size != 64) {
            return AuthenticatorClientPINResponse(CtapStatusCode.CTAP1_ERR_INVALID_PARAMETER)
        }
        //spec| Step 8: The authenticator drops all trailing 0x00 bytes from paddedNewPin to produce newPin.
        val sentinelPos = newPIN.indexOf(0x00)
        val trimmedNewPIN: ByteArray = when {
            (sentinelPos < 0) -> newPIN
            else -> newPIN.copyOf(sentinelPos)
        }
        //spec| Step 9: The authenticator checks the length of newPin against the current minimum PIN length,
        //spec| returning CTAP2_ERR_PIN_POLICY_VIOLATION if it is too short.
        if (trimmedNewPIN.size < 4) {
            return AuthenticatorClientPINResponse(CtapStatusCode.CTAP2_ERR_PIN_POLICY_VIOLATION)
        }
        //spec| Step 10: An authenticator MAY impose arbitrary, additional constraints on PINs. If newPin fails to
        //spec| satisfy such additional constraints, the authenticator returns CTAP2_ERR_PIN_POLICY_VIOLATION.
        if (trimmedNewPIN.size > 63) {
            return AuthenticatorClientPINResponse(CtapStatusCode.CTAP2_ERR_PIN_POLICY_VIOLATION)
        }
        // TODO: Step 11: remember newPin length as PINCodePointLength (needed when authenticatorConfig setMinPINLength is implemented)
        //spec| Step 12: The authenticator stores LEFT(SHA-256(newPin), 16) internally as CurrentStoredPIN,
        //spec| sets the pinRetries counter to maximum count, and returns CTAP2_OK.
        authenticatorPropertyStore.saveClientPIN(
            Arrays.copyOf(MessageDigestUtil.createSHA256().digest(trimmedNewPIN), 16)
        )
        authenticatorPropertyStore.savePINRetries(MAX_PIN_RETRIES)
        authenticatorPropertyStore.saveUVRetries(MAX_UV_RETRIES)
        // Reset all pinUvAuthTokens (not a spec step in §6.5.5.5, but necessary for security)
        pinUvAuthProtocols.forEach { it.resetPinUvAuthToken() }
        return AuthenticatorClientPINResponse(CtapStatusCode.CTAP2_OK)
    }

    //spec| 6.5.5.6. Changing existing PIN
    //spec| subCommand: changePIN (0x04)
    //spec| The following operations are performed to change an existing PIN:
    //spec| The Platform collects the current PIN (curPinUnicode) and new PIN (newPinUnicode) from the user as
    //spec| Unicode characters in Normalization Form C. Platform obtains the shared secret from the authenticator
    //spec| and sends the authenticatorClientPIN command with changePIN(0x04) subCommand.
    //spec| Authenticator performs following operations upon receiving the request:
    //spec|   1. If the authenticator does not receive mandatory parameters for this command,
    //spec|      it returns CTAP2_ERR_MISSING_PARAMETER error.
    //spec|   2. If pinUvAuthProtocol is not supported, return CTAP1_ERR_INVALID_PARAMETER.
    //spec|   3. If the pinRetries counter is 0, return CTAP2_ERR_PIN_BLOCKED error.
    //spec|   4. The authenticator calls decapsulate on the provided platform key-agreement key to obtain the shared
    //spec|      secret. If an error results, it returns CTAP1_ERR_INVALID_PARAMETER.
    //spec|   5. The authenticator calls verify(shared secret, newPinEnc || pinHashEnc, pinUvAuthParam)
    //spec|      5.1. If an error results, it returns CTAP2_ERR_PIN_AUTH_INVALID.
    //spec|   6. The authenticator decrements the pinRetries counter by 1.
    //spec|   7. The authenticator decrypts pinHashEnc using decrypt(shared secret, pinHashEnc) and verifies against its
    //spec|      internal stored LEFT(SHA-256(curPin), 16).
    //spec|      7.1. If an error results, or a mismatch is detected, the authenticator performs the following operations:
    //spec|           7.1.1. Calls regenerate for the selected pinUvAuthProtocol.
    //spec|           7.1.2. The authenticator returns errors according to following conditions:
    //spec|                  - If the pinRetries counter is 0, return CTAP2_ERR_PIN_BLOCKED error.
    //spec|                  - If the authenticator sees 3 consecutive mismatches, it returns CTAP2_ERR_PIN_AUTH_BLOCKED,
    //spec|                    indicating that power cycling is needed for further operations. This is done so that malware
    //spec|                    running on the platform should not be able to block the device without user interaction.
    //spec|                  - Else return CTAP2_ERR_PIN_INVALID error.
    //spec|   8. The authenticator sets the pinRetries counter to maximum value.
    //spec|   9. The authenticator calls decrypt(shared secret, newPinEnc) to produce paddedNewPin. If an error results,
    //spec|      it returns CTAP2_ERR_PIN_AUTH_INVALID.
    //spec|   10. If paddedNewPin is NOT 64 bytes long, it returns CTAP1_ERR_INVALID_PARAMETER.
    //spec|   11. The authenticator drops all trailing 0x00 bytes from paddedNewPin to produce newPin.
    //spec|   12. The authenticator checks the length of newPin against the current minimum PIN length, returning
    //spec|       CTAP2_ERR_PIN_POLICY_VIOLATION if it is too short.
    //spec|   13. If the forcePINChange member of the authenticatorGetInfo response is true and LEFT(SHA-256(newPin), 16)
    //spec|       is equal to its internal stored LEFT(SHA-256(curPin), 16) then authenticator returns
    //spec|       CTAP2_ERR_PIN_POLICY_VIOLATION.
    //spec|   14. An authenticator MAY impose arbitrary, additional constraints on PINs. If newPin fails to satisfy such
    //spec|       additional constraints, the authenticator returns CTAP2_ERR_PIN_POLICY_VIOLATION.
    //spec|   15. The authenticator remembers newPin length internally as PINCodePointLength.
    //spec|   16. The authenticator sets the value of the forcePINChange member of the authenticatorGetInfo response to
    //spec|       false,
    //spec|   17. The authenticator stores LEFT(SHA-256(newPin), 16) internally as the new value of CurrentStoredPIN.
    //spec|   18. The authenticator sets the pinRetries counter to maximum count.
    //spec|   19. The authenticator calls resetPinUvAuthToken() for all pinUvAuthProtocols supported by this
    //spec|       authenticator. (I.e. all existing pinUvAuthTokens are invalidated.)
    //spec|   20. The authenticator calls resetPersistentPinUvAuthToken() (all persistent permissions are cleared on pin
    //spec|       change).
    //spec|   21. The authenticator returns CTAP2_OK.
    // @see <a href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#changingExistingPin">§6.5.5.6</a>
    fun changePIN(
        pinProtocol: PinProtocolVersion,
        platformKeyAgreementKey: COSEKey?,
        pinAuth: ByteArray?,
        newPinEnc: ByteArray?,
        pinHashEnc: ByteArray?
    ): AuthenticatorClientPINResponse {
        //spec| Step 1: If the authenticator does not receive mandatory parameters for this command,
        //spec| it returns CTAP2_ERR_MISSING_PARAMETER error.
        if (platformKeyAgreementKey == null || pinAuth == null || newPinEnc == null || pinHashEnc == null) {
            return AuthenticatorClientPINResponse(CtapStatusCode.CTAP2_ERR_MISSING_PARAMETER)
        }
        //spec| Step 2: If pinUvAuthProtocol is not supported, return CTAP1_ERR_INVALID_PARAMETER.
        val protocol = getProtocol(pinProtocol)
        //spec| Step 3: If the pinRetries counter is 0, return CTAP2_ERR_PIN_BLOCKED error.
        if (authenticatorPropertyStore.loadPINRetries() == 0u) {
            return AuthenticatorClientPINResponse(CtapStatusCode.CTAP2_ERR_PIN_BLOCKED)
        }

        //spec| Step 4: The authenticator calls decapsulate on the provided platform key-agreement key
        //spec| to obtain the shared secret. If an error results, it returns CTAP1_ERR_INVALID_PARAMETER.
        val sharedSecret = protocol.decapsulate(platformKeyAgreementKey)
        //spec| Step 5: The authenticator calls verify(shared secret, newPinEnc || pinHashEnc, pinUvAuthParam)
        //spec| If an error results, it returns CTAP2_ERR_PIN_AUTH_INVALID.
        val joined =
            ByteBuffer.allocate(newPinEnc.size + pinHashEnc.size).put(newPinEnc).put(pinHashEnc)
                .array()
        if (!protocol.verify(sharedSecret, joined, pinAuth)) {
            return AuthenticatorClientPINResponse(CtapStatusCode.CTAP2_ERR_PIN_AUTH_INVALID)
        }
        //spec| Step 6: The authenticator decrements the pinRetries counter by 1.
        authenticatorPropertyStore.savePINRetries(authenticatorPropertyStore.loadPINRetries() - 1u)

        //spec| Step 7: The authenticator decrypts pinHashEnc using decrypt(shared secret, pinHashEnc)
        //spec| and verifies against its internal stored LEFT(SHA-256(curPin), 16).
        val pinHash = protocol.decrypt(sharedSecret, pinHashEnc)
        val storedPinHash =
            authenticatorPropertyStore.loadClientPIN() ?: return AuthenticatorClientPINResponse(
                CtapStatusCode.CTAP2_ERR_PIN_NOT_SET
            )

        if (!Arrays.equals(pinHash, storedPinHash)) {
            //spec| Step 7.1: If an error results, or a mismatch is detected, the authenticator performs the following operations:
            //spec| Step 7.1.1: Calls regenerate for the selected pinUvAuthProtocol.
            protocol.regenerate()
            volatilePinRetryCounter--
            //spec| Step 7.1.2: The authenticator returns errors according to following conditions:
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
        //spec| Step 8: The authenticator sets the pinRetries counter to maximum value.
        authenticatorPropertyStore.savePINRetries(MAX_PIN_RETRIES)
        authenticatorPropertyStore.saveUVRetries(MAX_UV_RETRIES)
        volatilePinRetryCounter = MAX_VOLATILE_PIN_RETRIES
        //spec| Step 9: The authenticator calls decrypt(shared secret, newPinEnc) to produce paddedNewPin.
        //spec| If an error results, it returns CTAP2_ERR_PIN_AUTH_INVALID.
        val newPIN = protocol.decrypt(sharedSecret, newPinEnc)
        //spec| Step 10: If paddedNewPin is NOT 64 bytes long, it returns CTAP1_ERR_INVALID_PARAMETER.
        if (newPIN.size != 64) {
            return AuthenticatorClientPINResponse(CtapStatusCode.CTAP1_ERR_INVALID_PARAMETER)
        }
        //spec| Step 11: The authenticator drops all trailing 0x00 bytes from paddedNewPin to produce newPin.
        val sentinelPos = ArrayUtil.indexOf(newPIN, 0x00.toByte())
        if (sentinelPos < 0) {
            return AuthenticatorClientPINResponse(CtapStatusCode.CTAP2_ERR_PIN_POLICY_VIOLATION)
        }
        val trimmedNewPIN = newPIN.copyOf(sentinelPos)
        //spec| Step 12: The authenticator checks the length of newPin against the current minimum PIN length,
        //spec| returning CTAP2_ERR_PIN_POLICY_VIOLATION if it is too short.
        if (trimmedNewPIN.size < 4) {
            return AuthenticatorClientPINResponse(CtapStatusCode.CTAP2_ERR_PIN_POLICY_VIOLATION)
        }
        // TODO: Step 13: forcePINChange check (needed when authenticatorConfig setMinPINLength is implemented)
        //spec| Step 14: An authenticator MAY impose arbitrary, additional constraints on PINs. If newPin fails to
        //spec| satisfy such additional constraints, the authenticator returns CTAP2_ERR_PIN_POLICY_VIOLATION.
        if (trimmedNewPIN.size > 63) {
            return AuthenticatorClientPINResponse(CtapStatusCode.CTAP2_ERR_PIN_POLICY_VIOLATION)
        }
        // TODO: Step 15: remember newPin length as PINCodePointLength (needed when authenticatorConfig setMinPINLength is implemented)
        // TODO: Step 16: set forcePINChange to false (needed when authenticatorConfig setMinPINLength is implemented)
        //spec| Step 17: The authenticator stores LEFT(SHA-256(newPin), 16) internally as the new value of CurrentStoredPIN.
        authenticatorPropertyStore.saveClientPIN(
            Arrays.copyOf(MessageDigestUtil.createSHA256().digest(trimmedNewPIN), 16)
        )
        //spec| Step 18: The authenticator sets the pinRetries counter to maximum count.
        // (already done at Step 8)
        //spec| Step 19: The authenticator calls resetPinUvAuthToken() for all pinUvAuthProtocols supported by this authenticator.
        pinUvAuthProtocols.forEach { it.resetPinUvAuthToken() }
        // TODO: Step 20: resetPersistentPinUvAuthToken (needed when authenticatorCredentialManagement is implemented)
        //spec| Step 21: The authenticator returns CTAP2_OK.
        return AuthenticatorClientPINResponse(CtapStatusCode.CTAP2_OK)
    }

    //spec| 6.5.5.7.1. Getting pinUvAuthToken using getPinToken (superseded)
    //spec| subCommand: getPinToken (0x05)
    //spec| Platform collects PIN from the user. Platform obtains the shared secret from the authenticator and sends
    //spec| the authenticatorClientPIN command with getPinToken(0x05) subCommand.
    //spec| Authenticator performs following operations upon receiving the request:
    //spec|   1. If the authenticator does not receive mandatory parameters for this command,
    //spec|      it returns CTAP2_ERR_MISSING_PARAMETER error.
    //spec|   2. If pinUvAuthProtocol is not supported, return CTAP1_ERR_INVALID_PARAMETER.
    //spec|   3. If authenticatorClientPIN's permissions parameter is present in the getPinToken (0x05) subcommand,
    //spec|      return CTAP1_ERR_INVALID_PARAMETER.
    //spec|   4. If authenticatorClientPIN's rpId parameter is present in the getPinToken (0x05) subcommand,
    //spec|      return CTAP1_ERR_INVALID_PARAMETER.
    //spec|   5. If the pinRetries counter is 0, return CTAP2_ERR_PIN_BLOCKED error.
    //spec|   6. The authenticator calls decapsulate on the provided platform key-agreement key to obtain the shared
    //spec|      secret. If an error results, it returns CTAP1_ERR_INVALID_PARAMETER.
    //spec|   7. If the authenticator has a display, request user consent for the default permissions. If this is not
    //spec|      approved, return CTAP2_ERR_OPERATION_DENIED.
    //spec|   8. The authenticator decrements the pinRetries counter by 1.
    //spec|   9. The authenticator decrypts pinHashEnc using decrypt and verifies against its internally stored
    //spec|      CurrentStoredPIN.
    //spec|      9.1. If an error results, or a mismatch is detected, the authenticator performs the following operations:
    //spec|           9.1.1. Calls regenerate for the selected pinUvAuthProtocol.
    //spec|           9.1.2. The authenticator returns errors according to following conditions:
    //spec|                  - If the pinRetries counter is 0, return CTAP2_ERR_PIN_BLOCKED error.
    //spec|                  - If the authenticator sees 3 consecutive mismatches, it returns CTAP2_ERR_PIN_AUTH_BLOCKED,
    //spec|                    indicating that power cycling is needed for further operations. This is done so that malware
    //spec|                    running on the platform should not be able to block the device without user interaction.
    //spec|                  - Else return CTAP2_ERR_PIN_INVALID error.
    //spec|   10. The authenticator sets the pinRetries counter to maximum value.
    //spec|   11. If the value of the forcePINChange member of the authenticatorGetInfo response is true,
    //spec|       authenticator returns CTAP2_ERR_PIN_INVALID error.
    //spec|   12. Create a new pinUvAuthToken by calling resetPinUvAuthToken() for all pinUvAuthProtocols supported by
    //spec|       this authenticator. (I.e. all existing pinUvAuthTokens are invalidated.)
    //spec|   13. Call beginUsingPinUvAuthToken(userIsPresent: false).
    //spec|   14. If the noMcGaPermissionsWithClientPin option ID is present and set to false, or absent, then assign
    //spec|       the pinUvAuthToken the default permissions.
    //spec|   15. The authenticator returns the encrypted pinUvAuthToken for the specified pinUvAuthProtocol, i.e.
    //spec|       encrypt(shared secret, pinUvAuthToken).
    // @see <a href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#getPinToken">§6.5.5.7.1</a>
    fun getPinToken(
        pinProtocol: PinProtocolVersion,
        platformKeyAgreementKey: COSEKey?,
        pinHashEnc: ByteArray?
    ): AuthenticatorClientPINResponse {
        //spec| Step 1: If the authenticator does not receive mandatory parameters for this command,
        //spec| it returns CTAP2_ERR_MISSING_PARAMETER error.
        if (platformKeyAgreementKey == null || pinHashEnc == null) {
            return AuthenticatorClientPINResponse(CtapStatusCode.CTAP2_ERR_MISSING_PARAMETER)
        }
        //spec| Step 2: If pinUvAuthProtocol is not supported, return CTAP1_ERR_INVALID_PARAMETER.
        val protocol = getProtocol(pinProtocol)
        // TODO: Step 3: If authenticatorClientPIN's permissions parameter is present in the getPinToken (0x05)
        // subcommand, return CTAP1_ERR_INVALID_PARAMETER.
        // TODO: Step 4: If authenticatorClientPIN's rpId parameter is present in the getPinToken (0x05)
        // subcommand, return CTAP1_ERR_INVALID_PARAMETER.
        //spec| Step 5: If the pinRetries counter is 0, return CTAP2_ERR_PIN_BLOCKED error.
        if (authenticatorPropertyStore.loadPINRetries() == 0u) {
            return AuthenticatorClientPINResponse(CtapStatusCode.CTAP2_ERR_PIN_BLOCKED)
        }
        // Guard for PIN_AUTH_BLOCKED state (enforces Step 9.1.2 across calls; resets on power cycle)
        if (volatilePinRetryCounter <= 0) {
            return AuthenticatorClientPINResponse(CtapStatusCode.CTAP2_ERR_PIN_AUTH_BLOCKED)
        }

        //spec| Step 6: The authenticator calls decapsulate on the provided platform key-agreement key
        //spec| to obtain the shared secret. If an error results, it returns CTAP1_ERR_INVALID_PARAMETER.
        val sharedSecret = protocol.decapsulate(platformKeyAgreementKey)
        // TODO: Step 7: request user consent if the authenticator has a display
        //spec| Step 8: The authenticator decrements the pinRetries counter by 1.
        authenticatorPropertyStore.savePINRetries(authenticatorPropertyStore.loadPINRetries() - 1u)

        //spec| Step 9: The authenticator decrypts pinHashEnc using decrypt and verifies against its
        //spec| internally stored CurrentStoredPIN.
        val pinHash = protocol.decrypt(sharedSecret, pinHashEnc)
        val storedPinHash =
            authenticatorPropertyStore.loadClientPIN() ?: return AuthenticatorClientPINResponse(
                CtapStatusCode.CTAP2_ERR_PIN_NOT_SET
            )
        if (!Arrays.equals(pinHash, storedPinHash)) {
            //spec| Step 9.1: If an error results, or a mismatch is detected, the authenticator performs the following operations:
            //spec| Step 9.1.1: Calls regenerate for the selected pinUvAuthProtocol.
            protocol.regenerate()
            volatilePinRetryCounter--
            //spec| Step 9.1.2: The authenticator returns errors according to following conditions:
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
        //spec| Step 10: The authenticator sets the pinRetries counter to maximum value.
        authenticatorPropertyStore.savePINRetries(MAX_PIN_RETRIES)
        authenticatorPropertyStore.saveUVRetries(MAX_UV_RETRIES)
        volatilePinRetryCounter = MAX_VOLATILE_PIN_RETRIES
        // TODO: Step 11: forcePINChange check (needed when authenticatorConfig setMinPINLength is implemented)
        //spec| Step 12: Create a new pinUvAuthToken by calling resetPinUvAuthToken() for all pinUvAuthProtocols
        //spec| supported by this authenticator.
        pinUvAuthProtocols.forEach { it.resetPinUvAuthToken() }
        //spec| Step 13: Call beginUsingPinUvAuthToken(userIsPresent: false).
        protocol.tokenState.beginUsingPinUvAuthToken(false)
        //spec| Step 14: If the noMcGaPermissionsWithClientPin option ID is present and set to false, or absent,
        //spec| then assign the pinUvAuthToken the default permissions.
        // noMcGaPermissionsWithClientPin option is absent, so default permissions (mc|ga) are granted.
        protocol.tokenState.permissions = PinUvAuthTokenPermissions(PinUvAuthTokenPermission.MC, PinUvAuthTokenPermission.GA)
        //spec| Step 15: The authenticator returns the encrypted pinUvAuthToken for the specified pinUvAuthProtocol,
        //spec| i.e. encrypt(shared secret, pinUvAuthToken).
        val pinTokenEnc = protocol.encrypt(sharedSecret, protocol.pinUvAuthToken)
        val responseData =
            AuthenticatorClientPINResponseData(null, pinTokenEnc, null)
        return AuthenticatorClientPINResponse(CtapStatusCode.CTAP2_OK, responseData)
    }

    //spec| 6.5.5.7.2. Getting pinUvAuthToken using getPinUvAuthTokenUsingPinWithPermissions (ClientPIN)
    //spec| subCommand: getPinUvAuthTokenUsingPinWithPermissions (0x09)
    //spec| This subCommand MUST be implemented if the authenticator includes both clientPin and pinUvAuthToken
    //spec| Option IDs set to true in the authenticatorGetInfo response.
    //spec| Platform collects PIN from the user. Platform obtains the shared secret from the authenticator and sends
    //spec| the authenticatorClientPIN command with getPinUvAuthTokenUsingPinWithPermissions(0x09) subCommand.
    //spec| Authenticator performs following operations upon receiving the request:
    //spec|   1. If the authenticator does not receive mandatory parameters for this command,
    //spec|      it returns CTAP2_ERR_MISSING_PARAMETER error.
    //spec|   2. If pinUvAuthProtocol is not supported, return CTAP1_ERR_INVALID_PARAMETER.
    //spec|   3. If the authenticator receives a permissions parameter with value 0, return
    //spec|      CTAP1_ERR_INVALID_PARAMETER.
    //spec|   4. The below statements each relate a pinUvAuthToken permission to a given state for a
    //spec|      authenticatorGetInfo option ID. For each pinUvAuthToken permission present in the permissions parameter,
    //spec|      if the statement corresponding to the permission is currently true, terminate these steps and return
    //spec|      CTAP2_ERR_UNAUTHORIZED_PERMISSION. Undefined permissions present in the permissions parameter are ignored.
    //spec|      - cm: credMgmt is false or absent.
    //spec|      - be: bioEnroll is absent.
    //spec|      - lbw: largeBlobs is false or absent.
    //spec|      - acfg: authnrCfg is false or absent.
    //spec|      - mc: noMcGaPermissionsWithClientPin is present and set to true.
    //spec|      - ga: noMcGaPermissionsWithClientPin is present and set to true.
    //spec|      - pcmr: perCredMgmtRO is false or absent, or any other pinUvAuthToken permission is requested.
    //spec|   5. If the pinRetries counter is 0, return CTAP2_ERR_PIN_BLOCKED error.
    //spec|   6. The authenticator calls decapsulate on the provided platform key-agreement key to obtain the shared
    //spec|      secret. If an error results, it returns CTAP1_ERR_INVALID_PARAMETER.
    //spec|   7. If the authenticator has a display, request user consent for the requested permissions. If this is not
    //spec|      approved, return CTAP2_ERR_OPERATION_DENIED.
    //spec|   8. The authenticator decrements the pinRetries counter by 1.
    //spec|   9. The authenticator decrypts pinHashEnc using decrypt and verifies against its internally stored
    //spec|      CurrentStoredPIN.
    //spec|      9.1. If an error results, or a mismatch is detected, the authenticator performs the following operations:
    //spec|           9.1.1. Calls regenerate for the selected pinUvAuthProtocol.
    //spec|           9.1.2. The authenticator returns errors according to following conditions:
    //spec|                  - If the pinRetries counter is 0, return CTAP2_ERR_PIN_BLOCKED error.
    //spec|                  - If the authenticator sees 3 consecutive mismatches, it returns CTAP2_ERR_PIN_AUTH_BLOCKED,
    //spec|                    indicating that power cycling is needed for further operations. This is done so that malware
    //spec|                    running on the platform should not be able to block the device without user interaction.
    //spec|                  - Else return CTAP2_ERR_PIN_INVALID error.
    //spec|   10. The authenticator sets the pinRetries counter to maximum value.
    //spec|   11. If the value of the forcePINChange member of the authenticatorGetInfo response is true,
    //spec|       authenticator returns CTAP2_ERR_PIN_POLICY_VIOLATION.
    //spec|       Platform on receiving such error response SHOULD direct the user to change the PIN.
    //spec|   12. If the value of the requested permissions is pcmr:
    //spec|       12.1. Assign pcmr permission to the persistentPinUvAuthToken.
    //spec|       12.2. The authenticator returns the encrypted persistentPinUvAuthToken for the specified
    //spec|             pinUvAuthProtocol, i.e. encrypt(shared secret, persistentPinUvAuthToken).
    //spec|   13. Create a new pinUvAuthToken by calling resetPinUvAuthToken() for all pinUvAuthProtocols supported by
    //spec|       this authenticator. (I.e. all existing pinUvAuthTokens are invalidated.)
    //spec|   14. Call beginUsingPinUvAuthToken(userIsPresent: false).
    //spec|   15. Assign the requested permissions to the pinUvAuthToken, ignoring any undefined permissions.
    //spec|   16. If the rpId parameter is present, associate the permissions RP ID with the pinUvAuthToken.
    //spec|   17. The authenticator returns the encrypted pinUvAuthToken for the specified pinUvAuthProtocol, i.e.
    //spec|       encrypt(shared secret, pinUvAuthToken).
    // @see <a href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#getPinUvAuthTokenUsingPinWithPermissions">§6.5.5.7.2</a>
    fun getPinUvAuthTokenUsingPinWithPermissions(
        pinProtocol: PinProtocolVersion,
        platformKeyAgreementKey: COSEKey?,
        pinHashEnc: ByteArray?,
        permissions: PinUvAuthTokenPermissions?,
        rpId: String?
    ): AuthenticatorClientPINResponse {
        //spec| Step 1: If the authenticator does not receive mandatory parameters for this command,
        //spec| it returns CTAP2_ERR_MISSING_PARAMETER error.
        if (platformKeyAgreementKey == null || pinHashEnc == null || permissions == null) {
            return AuthenticatorClientPINResponse(CtapStatusCode.CTAP2_ERR_MISSING_PARAMETER)
        }

        //spec| Step 2: If pinUvAuthProtocol is not supported, return CTAP1_ERR_INVALID_PARAMETER.
        val protocol = getProtocol(pinProtocol)
        //spec| Step 3: If the authenticator receives a permissions parameter with value 0,
        //spec| return CTAP1_ERR_INVALID_PARAMETER.
        if (permissions.isEmpty()) {
            return AuthenticatorClientPINResponse(CtapStatusCode.CTAP1_ERR_INVALID_PARAMETER)
        }

        //spec| Step 4: Validate requested permissions against authenticator capabilities.
        for (permission in permissions) {
            when (permission) {
                PinUvAuthTokenPermission.MC, PinUvAuthTokenPermission.GA -> {
                    // Always authorized for PIN-based token issuance
                }
                PinUvAuthTokenPermission.CM -> {
                    // TODO: check credMgmt option when authenticatorCredentialManagement is implemented
                    return AuthenticatorClientPINResponse(CtapStatusCode.CTAP2_ERR_UNAUTHORIZED_PERMISSION)
                }
                PinUvAuthTokenPermission.BE -> {
                    // TODO: check bioEnroll option when authenticatorBioEnrollment is implemented
                    return AuthenticatorClientPINResponse(CtapStatusCode.CTAP2_ERR_UNAUTHORIZED_PERMISSION)
                }
                PinUvAuthTokenPermission.LBW -> {
                    // TODO: check largeBlobs option when authenticatorLargeBlobs is implemented
                    return AuthenticatorClientPINResponse(CtapStatusCode.CTAP2_ERR_UNAUTHORIZED_PERMISSION)
                }
                PinUvAuthTokenPermission.ACFG -> {
                    // TODO: check authnrCfg option when authenticatorConfig is implemented
                    return AuthenticatorClientPINResponse(CtapStatusCode.CTAP2_ERR_UNAUTHORIZED_PERMISSION)
                }
            }
        }

        //spec| Step 5: If the pinRetries counter is 0, return CTAP2_ERR_PIN_BLOCKED error.
        if (authenticatorPropertyStore.loadPINRetries() == 0u) {
            return AuthenticatorClientPINResponse(CtapStatusCode.CTAP2_ERR_PIN_BLOCKED)
        }
        // Guard for PIN_AUTH_BLOCKED state (enforces Step 9.1.2 across calls; resets on power cycle)
        if (volatilePinRetryCounter <= 0) {
            return AuthenticatorClientPINResponse(CtapStatusCode.CTAP2_ERR_PIN_AUTH_BLOCKED)
        }

        //spec| Step 6: The authenticator calls decapsulate on the provided platform key-agreement key
        //spec| to obtain the shared secret. If an error results, it returns CTAP1_ERR_INVALID_PARAMETER.
        val sharedSecret = protocol.decapsulate(platformKeyAgreementKey)
        // TODO: Step 7: request user consent if the authenticator has a display

        //spec| Step 8: The authenticator decrements the pinRetries counter by 1.
        authenticatorPropertyStore.savePINRetries(authenticatorPropertyStore.loadPINRetries() - 1u)

        //spec| Step 9: The authenticator decrypts pinHashEnc and verifies against its internally stored
        //spec| CurrentStoredPIN.
        val pinHash = protocol.decrypt(sharedSecret, pinHashEnc)
        val storedPinHash =
            authenticatorPropertyStore.loadClientPIN() ?: return AuthenticatorClientPINResponse(
                CtapStatusCode.CTAP2_ERR_PIN_NOT_SET
            )
        if (!Arrays.equals(pinHash, storedPinHash)) {
            //spec| Step 9.1: If an error results, or a mismatch is detected, the authenticator performs the following operations:
            //spec| Step 9.1.1: Calls regenerate for the selected pinUvAuthProtocol.
            protocol.regenerate()
            volatilePinRetryCounter--
            //spec| Step 9.1.2: The authenticator returns errors according to following conditions:
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

        //spec| Step 10: The authenticator sets the pinRetries counter to maximum value.
        authenticatorPropertyStore.savePINRetries(MAX_PIN_RETRIES)
        authenticatorPropertyStore.saveUVRetries(MAX_UV_RETRIES)
        volatilePinRetryCounter = MAX_VOLATILE_PIN_RETRIES

        // TODO: Step 11: forcePINChange check (needed when authenticatorConfig setMinPINLength is implemented)
        // TODO: Step 12: pcmr permission handling (needed when authenticatorCredentialManagement is implemented)

        //spec| Step 13: Create a new pinUvAuthToken by calling resetPinUvAuthToken() for all
        //spec| pinUvAuthProtocols supported by this authenticator.
        for (p in pinUvAuthProtocols) {
            p.resetPinUvAuthToken()
        }

        //spec| Step 14: Call beginUsingPinUvAuthToken(userIsPresent: false).
        protocol.tokenState.beginUsingPinUvAuthToken(false)

        //spec| Step 15: Assign the requested permissions to the pinUvAuthToken, ignoring any undefined permissions.
        protocol.tokenState.permissions = permissions

        //spec| Step 16: If the rpId parameter is present, associate the permissions RP ID with the pinUvAuthToken.
        if (rpId != null) {
            protocol.tokenState.permissionsRpId = rpId
        }

        //spec| Step 17: The authenticator returns the encrypted pinUvAuthToken for the specified pinUvAuthProtocol,
        //spec| i.e. encrypt(shared secret, pinUvAuthToken).
        val pinTokenEnc = protocol.encrypt(sharedSecret, protocol.pinUvAuthToken)
        val responseData = AuthenticatorClientPINResponseData(null, pinTokenEnc, null)
        return AuthenticatorClientPINResponse(CtapStatusCode.CTAP2_OK, responseData)
    }

    //spec| 6.5.5.7.3. Getting pinUvAuthToken using getPinUvAuthTokenUsingUvWithPermissions (built-in user
    //spec| verification methods)
    //spec| subCommand: getPinUvAuthTokenUsingUvWithPermissions (0x06)
    //spec| This subCommand is only applicable when the authenticator supports built-in user verification methods.
    //spec| This subCommand MUST be implemented if the authenticator returns both uv and pinUvAuthToken option IDs
    //spec| set to true in the authenticatorGetInfo response.
    //spec| Platform obtains the shared secret from the authenticator and sends the authenticatorClientPIN command
    //spec| with getPinUvAuthTokenUsingUvWithPermissions(0x06) subCommand.
    //spec| Authenticator performs following operations upon receiving the request:
    //spec|   1. If the authenticator does not receive mandatory parameters for this command,
    //spec|      it returns CTAP2_ERR_MISSING_PARAMETER error.
    //spec|   2. If pinUvAuthProtocol is not supported, return CTAP1_ERR_INVALID_PARAMETER.
    //spec|   3. If the authenticator receives a permissions parameter with value 0, return
    //spec|      CTAP1_ERR_INVALID_PARAMETER.
    //spec|   4. The below statements each relate a pinUvAuthToken permission to a given state for a
    //spec|      authenticatorGetInfo option ID. For each pinUvAuthToken permission present in the permissions parameter,
    //spec|      if the statement corresponding to the permission is currently true, terminate these steps and return
    //spec|      CTAP2_ERR_UNAUTHORIZED_PERMISSION. The mc and ga permissions are always considered authorized, thus they
    //spec|      are not listed below. Undefined permissions present in the permissions are ignored.
    //spec|      - cm: credMgmt is false or absent.
    //spec|      - be: uvBioEnroll is false or absent.
    //spec|      - lbw: largeBlobs is false or absent.
    //spec|      - acfg: uvAcfg is false or absent.
    //spec|      - pcmr: perCredMgmtRO is false or absent, or any other pinUvAuthToken permission is requested.
    //spec|   5. If a built-in user verification method is supported but not configured, the authenticator
    //spec|      returns CTAP2_ERR_NOT_ALLOWED.
    //spec|   6. If preferredPlatformUvAttempts > 1 then let internalRetry be false. This indicates that the platform
    //spec|      will try invoking this sub command preferably about preferredPlatformUvAttempts times.
    //spec|      Else let internalRetry be true.
    //spec|   7. If the uvRetries counter is 0, return CTAP2_ERR_UV_BLOCKED error.
    //spec|   8. If the authenticator has a display, request user consent for the requested permissions. If this is not
    //spec|      approved, return CTAP2_ERR_OPERATION_DENIED.
    //spec|   9. Let uvState be the result of calling performBuiltInUv(internalRetry)
    //spec|   10. If uvState is error:
    //spec|       10.1. If the error reason is a user action timeout, then return CTAP2_ERR_USER_ACTION_TIMEOUT.
    //spec|       10.2. If the uvRetries counter is 0, return CTAP2_ERR_UV_BLOCKED.
    //spec|       10.3. Otherwise, return CTAP2_ERR_UV_INVALID.
    //spec|   11. If the value of the requested permissions is pcmr:
    //spec|       11.1. Assign pcmr permission to the persistentPinUvAuthToken.
    //spec|       11.2. The authenticator returns the encrypted persistentPinUvAuthToken for the specified
    //spec|             pinUvAuthProtocol, i.e. encrypt(shared secret, persistentPinUvAuthToken).
    //spec|   12. Create a new pinUvAuthToken by calling resetPinUvAuthToken() for all pinUvAuthProtocols supported by
    //spec|       this authenticator. (I.e. all existing pinUvAuthTokens are invalidated.)
    //spec|   13. If the employed built-in user verification method supplied evidence of user interaction, then call
    //spec|       beginUsingPinUvAuthToken(userIsPresent: true).
    //spec|       Otherwise (implying that user presence was not collected), call
    //spec|       beginUsingPinUvAuthToken(userIsPresent: false).
    //spec|   14. Assign the requested permissions to the pinUvAuthToken, ignoring any undefined permissions.
    //spec|   15. If the rpId parameter is present, use its value as the permissions RP ID and associate it with the
    //spec|       pinUvAuthToken.
    //spec|   16. The authenticator returns the encrypted pinUvAuthToken for the specified pinUvAuthProtocol, i.e.
    //spec|       encrypt(shared secret, pinUvAuthToken).
    // @see <a href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#getPinUvAuthTokenUsingUvWithPermissions">§6.5.5.7.3</a>
    fun getPinUvAuthTokenUsingUvWithPermissions(
        pinProtocol: PinProtocolVersion,
        platformKeyAgreementKey: COSEKey?,
        permissions: PinUvAuthTokenPermissions?,
        rpId: String?
    ): AuthenticatorClientPINResponse {
        //spec| Step 1: If the authenticator does not receive mandatory parameters for this command,
        //spec| it returns CTAP2_ERR_MISSING_PARAMETER error.
        if (platformKeyAgreementKey == null || permissions == null) {
            return AuthenticatorClientPINResponse(CtapStatusCode.CTAP2_ERR_MISSING_PARAMETER)
        }

        //spec| Step 2: If pinUvAuthProtocol is not supported, return CTAP1_ERR_INVALID_PARAMETER.
        val protocol = getProtocol(pinProtocol)
        //spec| Step 3: If the authenticator receives a permissions parameter with value 0,
        //spec| return CTAP1_ERR_INVALID_PARAMETER.
        if (permissions.isEmpty()) {
            return AuthenticatorClientPINResponse(CtapStatusCode.CTAP1_ERR_INVALID_PARAMETER)
        }

        //spec| Step 4: Validate requested permissions against authenticator capabilities.
        for (permission in permissions) {
            when (permission) {
                PinUvAuthTokenPermission.MC, PinUvAuthTokenPermission.GA -> {
                    // Always authorized for UV-based token issuance
                }
                PinUvAuthTokenPermission.CM -> {
                    // TODO: check credMgmt option when authenticatorCredentialManagement is implemented
                    return AuthenticatorClientPINResponse(CtapStatusCode.CTAP2_ERR_UNAUTHORIZED_PERMISSION)
                }
                PinUvAuthTokenPermission.BE -> {
                    // TODO: check uvBioEnroll option when authenticatorBioEnrollment is implemented
                    return AuthenticatorClientPINResponse(CtapStatusCode.CTAP2_ERR_UNAUTHORIZED_PERMISSION)
                }
                PinUvAuthTokenPermission.LBW -> {
                    // TODO: check largeBlobs option when authenticatorLargeBlobs is implemented
                    return AuthenticatorClientPINResponse(CtapStatusCode.CTAP2_ERR_UNAUTHORIZED_PERMISSION)
                }
                PinUvAuthTokenPermission.ACFG -> {
                    // TODO: check uvAcfg option when authenticatorConfig is implemented
                    return AuthenticatorClientPINResponse(CtapStatusCode.CTAP2_ERR_UNAUTHORIZED_PERMISSION)
                }
            }
        }
        // TODO: Step 5: check if built-in UV is configured, return CTAP2_ERR_NOT_ALLOWED if not
        // TODO: Step 6: determine internalRetry based on preferredPlatformUvAttempts

        //spec| Step 7: If the uvRetries counter is 0, return CTAP2_ERR_UV_BLOCKED error.
        if (authenticatorPropertyStore.loadUVRetries() == 0u) {
            return AuthenticatorClientPINResponse(CtapStatusCode.CTAP2_ERR_UV_BLOCKED)
        }

        // Decapsulate the platform key-agreement key to obtain the shared secret
        // (implicit in the spec — needed for encrypt at Step 16)
        val sharedSecret = protocol.decapsulate(platformKeyAgreementKey)

        // TODO: Steps 8-9 (consent + built-in UV) are not yet implemented.
        //
        // The spec requires the authenticator to:
        //   Step 8: If the authenticator has a display, request user consent for the
        //           requested permissions. Return CTAP2_ERR_OPERATION_DENIED if denied.
        //   Step 9: Perform built-in user verification (e.g. biometric).
        //   Step 10: Handle UV failure (CTAP2_ERR_UV_INVALID, CTAP2_ERR_UV_BLOCKED,
        //            CTAP2_ERR_USER_ACTION_TIMEOUT).
        //
        // Currently, UV always succeeds without any actual verification.
        //
        // On Android, performing UV here is problematic because:
        //   - BiometricPrompt + CryptoObject ties biometric auth to key operations,
        //     but credential keys do not exist yet at this point (for makeCredential).
        //   - Only rpId and permissions are available as context; rp.name and
        //     user.displayName are not provided until makeCredential, making it
        //     difficult to show a meaningful consent dialog.
        //
        // A possible approach is "deferred UV": issue the pinUvAuthToken here without
        // performing actual biometric verification, record in the token state that UV
        // is pending (e.g. a uvDeferred flag on PinUvAuthTokenState), and perform the
        // actual biometric check later during makeCredential/getAssertion at the UP
        // step, where full operation context and CryptoObject binding are available.
        // From the client's perspective, the result is identical — the credential is
        // created with the UV bit set, and UV is performed before any key operation.

        // TODO: Step 11: pcmr permission handling (needed when authenticatorCredentialManagement is implemented)

        //spec| Step 12: Create a new pinUvAuthToken by calling resetPinUvAuthToken() for all
        //spec| pinUvAuthProtocols supported by this authenticator.
        for (p in pinUvAuthProtocols) {
            p.resetPinUvAuthToken()
        }

        //spec| Step 13: If the employed built-in user verification method supplied evidence of user interaction,
        //spec| then call beginUsingPinUvAuthToken(userIsPresent: true).
        //spec| Otherwise (implying that user presence was not collected),
        //spec| call beginUsingPinUvAuthToken(userIsPresent: false).
        // Our virtual authenticator's UV always implies user interaction
        protocol.tokenState.beginUsingPinUvAuthToken(true)

        //spec| Step 14: Assign the requested permissions to the pinUvAuthToken, ignoring any undefined permissions.
        protocol.tokenState.permissions = permissions

        //spec| Step 15: If the rpId parameter is present, use its value as the permissions RP ID and associate it with the pinUvAuthToken.
        if (rpId != null) {
            protocol.tokenState.permissionsRpId = rpId
        }

        // Reset retries counters after successful UV verification
        authenticatorPropertyStore.savePINRetries(MAX_PIN_RETRIES)
        authenticatorPropertyStore.saveUVRetries(MAX_UV_RETRIES)

        //spec| Step 16: The authenticator returns the encrypted pinUvAuthToken for the specified pinUvAuthProtocol,
        //spec| i.e. encrypt(shared secret, pinUvAuthToken).
        val pinTokenEnc = protocol.encrypt(sharedSecret, protocol.pinUvAuthToken)
        val responseData = AuthenticatorClientPINResponseData(null, pinTokenEnc, null)
        return AuthenticatorClientPINResponse(CtapStatusCode.CTAP2_OK, responseData)
    }

    //spec| 6.5.5.3. Platform getting UV Retries from Authenticator
    //spec| UV retries count is the number of built-in UV attempts remaining before built-in UV is disabled on
    //spec| the device. When the UV retries count nears zero, the platform can optionally warn the user to be
    //spec| careful while performing user verification.
    //spec| Platform performs the following operations to get uvRetries:
    //spec|   1. Platform sends authenticatorClientPIN command
    //spec|      with following parameters to the authenticator:
    //spec|        subCommand: getUVRetries(0x07)
    //spec|   2. Authenticator responds back with uvRetries.
    // @see <a href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#gettingUVRetries">§6.5.5.3</a>
    fun getUVRetries(): AuthenticatorClientPINResponse {
        //spec| Step 2: Authenticator responds back with uvRetries.
        val uvRetries = authenticatorPropertyStore.loadUVRetries()
        val responseData = AuthenticatorClientPINResponseData(null, null, null, null, uvRetries)
        return AuthenticatorClientPINResponse(CtapStatusCode.CTAP2_OK, responseData)
    }

    private fun getProtocol(pinProtocol: PinProtocolVersion): PinUvAuthProtocol {
        return pinUvAuthProtocols.firstOrNull { it.version == pinProtocol }
            ?: throw CtapCommandExecutionException(CtapStatusCode.CTAP1_ERR_INVALID_PARAMETER)
    }

}
