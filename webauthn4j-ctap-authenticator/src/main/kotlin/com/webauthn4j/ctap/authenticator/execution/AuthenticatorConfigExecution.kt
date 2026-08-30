package com.webauthn4j.ctap.authenticator.execution

import com.webauthn4j.ctap.authenticator.CtapAuthenticatorSession
import com.webauthn4j.ctap.authenticator.PinUvAuthManager
import com.webauthn4j.ctap.core.data.AuthenticatorConfigRequest
import com.webauthn4j.ctap.core.data.AuthenticatorConfigResponse
import com.webauthn4j.ctap.core.data.AuthenticatorConfigSubCommandEnum
import com.webauthn4j.ctap.core.data.CtapStatusCode
import com.webauthn4j.ctap.core.data.PinUvAuthTokenPermission
import org.slf4j.LoggerFactory

/**
 * authenticatorConfig (0x0D) command execution
 *
 * @see <a href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorConfig">6.8. authenticatorConfig</a>
 */
internal class AuthenticatorConfigExecution(
    private val ctapAuthenticatorSession: CtapAuthenticatorSession,
    private val authenticatorConfigRequest: AuthenticatorConfigRequest
) : CtapCommandExecutionBase<AuthenticatorConfigRequest, AuthenticatorConfigResponse>(
    ctapAuthenticatorSession,
    authenticatorConfigRequest
) {

    companion object {
        private const val MAX_RPIDS = 8
    }

    private val logger = LoggerFactory.getLogger(AuthenticatorConfigExecution::class.java)
    override val commandName: String = "AuthenticatorConfig"

    override suspend fun validate() {
        // Validation is done within doExecute per sub-command
    }

    override suspend fun doExecute(): AuthenticatorConfigResponse {
        return when (authenticatorConfigRequest.subCommand) {
            AuthenticatorConfigSubCommandEnum.SET_MIN_PIN_LENGTH -> {
                logger.debug("Processing authenticatorConfig setMinPINLength sub-command")
                handleSetMinPINLength()
            }
            // TODO: Implement enableEnterpriseAttestation
            AuthenticatorConfigSubCommandEnum.ENABLE_ENTERPRISE_ATTESTATION ->
                throw CtapCommandExecutionException(CtapStatusCode.CTAP1_ERR_INVALID_PARAMETER)
            // TODO: Implement toggleAlwaysUv
            AuthenticatorConfigSubCommandEnum.TOGGLE_ALWAYS_UV ->
                throw CtapCommandExecutionException(CtapStatusCode.CTAP1_ERR_INVALID_PARAMETER)
            // TODO: Implement enableLongTouchForReset
            AuthenticatorConfigSubCommandEnum.ENABLE_LONG_TOUCH_FOR_RESET ->
                throw CtapCommandExecutionException(CtapStatusCode.CTAP1_ERR_INVALID_PARAMETER)
            // TODO: Implement vendorPrototype
            AuthenticatorConfigSubCommandEnum.VENDOR_PROTOTYPE ->
                throw CtapCommandExecutionException(CtapStatusCode.CTAP1_ERR_INVALID_PARAMETER)
        }
    }

    /**
     * Verifies the pinUvAuthParam for authenticatorConfig commands.
     *
     * The message format for authenticatorConfig is:
     * 0xFF * 32 || 0x0D || subCommand || subCommandParams (canonical CBOR, or empty)
     */
    private fun verifyPinUvAuthParam() {
        val pinUvAuthParam = authenticatorConfigRequest.pinUvAuthParam
            ?: throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_PUAT_REQUIRED)

        val pinUvAuthProtocol = authenticatorConfigRequest.pinUvAuthProtocol
            ?: throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_MISSING_PARAMETER)

        val protocol = ctapAuthenticatorSession.pinUvAuthManager.pinUvAuthProtocols
            .firstOrNull { it.version == pinUvAuthProtocol }
            ?: throw CtapCommandExecutionException(CtapStatusCode.CTAP1_ERR_INVALID_PARAMETER)

        // Build message: 0xFF*32 || 0x0D || subCommand || subCommandParams
        val subCommandParamsBytes = if (authenticatorConfigRequest.subCommandParams != null) {
            ctapAuthenticatorSession.objectConverter.cborMapper.writeValueAsBytes(
                authenticatorConfigRequest.subCommandParams
            )
        } else {
            ByteArray(0)
        }

        val message = ByteArray(32) { 0xFF.toByte() } +
            byteArrayOf(0x0D) +
            byteArrayOf(authenticatorConfigRequest.subCommand.value.toByte()) +
            subCommandParamsBytes

        if (!protocol.verify(protocol.pinUvAuthToken, message, pinUvAuthParam)) {
            throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_PIN_AUTH_INVALID)
        }

        if (!protocol.tokenState.getUserVerifiedFlagValue()) {
            throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_PIN_AUTH_INVALID)
        }

        if (!protocol.tokenState.hasPermission(PinUvAuthTokenPermission.ACFG)) {
            throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_PIN_AUTH_INVALID)
        }

        protocol.tokenState.recordTokenUsage()
    }

    private fun handleSetMinPINLength(): AuthenticatorConfigResponse {
        // Verify pinUvAuthParam
        verifyPinUvAuthParam()

        val authenticatorPropertyStore = ctapAuthenticatorSession.authenticatorPropertyStore
        val subCommandParams = authenticatorConfigRequest.subCommandParams

        // Get current minPINLength
        val currentMinPINLength = authenticatorPropertyStore.loadProperty("minPINLength")?.toIntOrNull()
            ?: PinUvAuthManager.DEFAULT_MIN_PIN_LENGTH

        // Get new minPINLength (default to current if absent)
        val newMinPINLength = subCommandParams?.newMinPINLength?.toInt() ?: currentMinPINLength

        // New value must not be less than current
        if (newMinPINLength < currentMinPINLength) {
            throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_PIN_POLICY_VIOLATION)
        }

        // Handle forceChangePin
        val forceChangePin = subCommandParams?.forceChangePin == true
        if (forceChangePin) {
            if (authenticatorPropertyStore.loadClientPIN() == null) {
                throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_PIN_NOT_SET)
            }
            authenticatorPropertyStore.saveProperty("forcePINChange", "true")
        }

        // Handle minPinLengthRPIDs
        val rpIds = subCommandParams?.minPinLengthRPIDs
        if (rpIds != null) {
            if (rpIds.size > MAX_RPIDS) {
                throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_KEY_STORE_FULL)
            }
            authenticatorPropertyStore.saveProperty("minPinLengthRPIDs", rpIds.joinToString(","))
        }

        // Save new minPINLength
        authenticatorPropertyStore.saveProperty("minPINLength", newMinPINLength.toString())

        // If forcePINChange became true, invalidate all pinUvAuthTokens
        if (forceChangePin) {
            for (protocol in ctapAuthenticatorSession.pinUvAuthManager.pinUvAuthProtocols) {
                protocol.resetPinUvAuthToken()
            }
        }

        return AuthenticatorConfigResponse(CtapStatusCode.CTAP2_OK)
    }

    override fun createErrorResponse(statusCode: CtapStatusCode): AuthenticatorConfigResponse {
        return AuthenticatorConfigResponse(statusCode)
    }
}
