package com.webauthn4j.ctap.authenticator.execution

import com.webauthn4j.ctap.authenticator.CtapAuthenticatorSession
import com.webauthn4j.ctap.core.data.AuthenticatorClientPINRequest
import com.webauthn4j.ctap.core.data.AuthenticatorClientPINResponse
import com.webauthn4j.ctap.core.data.CtapStatusCode
import com.webauthn4j.ctap.core.data.PinSubCommand
import com.webauthn4j.ctap.core.validator.AuthenticatorClientPINRequestValidator
import org.slf4j.LoggerFactory

/**
 * Client PIN command execution
 */
internal class ClientPINExecution(
    private val ctapAuthenticatorSession: CtapAuthenticatorSession,
    private val authenticatorClientPINRequest: AuthenticatorClientPINRequest
) : CtapCommandExecutionBase<AuthenticatorClientPINRequest, AuthenticatorClientPINResponse>(
    ctapAuthenticatorSession,
    authenticatorClientPINRequest
) {
    private val logger = LoggerFactory.getLogger(ClientPINExecution::class.java)
    private val authenticatorClientPINRequestValidator = AuthenticatorClientPINRequestValidator()
    override val commandName: String = "ClientPIN"

    override suspend fun validate() {
        authenticatorClientPINRequestValidator.validate(authenticatorClientPINRequest)
    }

    override suspend fun doExecute(): AuthenticatorClientPINResponse {
        val pinUvAuthManager = ctapAuthenticatorSession.pinUvAuthManager
        val pinProtocol = authenticatorClientPINRequest.pinProtocol
        val platformKeyAgreementKey = authenticatorClientPINRequest.keyAgreement
        val pinAuth = authenticatorClientPINRequest.pinAuth
        val newPinEnc = authenticatorClientPINRequest.newPinEnc
        val pinHashEnc = authenticatorClientPINRequest.pinHashEnc
        val permissions = authenticatorClientPINRequest.permissions
        val rpId = authenticatorClientPINRequest.rpId
        return when (authenticatorClientPINRequest.subCommand) {
            PinSubCommand.GET_PIN_RETRIES -> {
                logger.debug("Processing clientPIN getRetries sub-command")
                pinUvAuthManager.getPinRetries()
            }
            PinSubCommand.GET_KEY_AGREEMENT -> {
                logger.debug("Processing clientPIN getKeyAgreement sub-command (protocol={})", pinProtocol)
                pinUvAuthManager.getKeyAgreement(pinProtocol)
            }
            PinSubCommand.SET_PIN -> {
                logger.debug("Processing clientPIN setPIN sub-command (protocol={})", pinProtocol)
                pinUvAuthManager.setPIN(pinProtocol, platformKeyAgreementKey, pinAuth, newPinEnc)
            }
            PinSubCommand.CHANGE_PIN -> {
                logger.debug("Processing clientPIN changePIN sub-command (protocol={})", pinProtocol)
                pinUvAuthManager.changePIN(pinProtocol, platformKeyAgreementKey, pinAuth, newPinEnc, pinHashEnc)
            }
            PinSubCommand.GET_PIN_TOKEN -> {
                logger.debug("Processing clientPIN getPINToken sub-command (protocol={})", pinProtocol)
                pinUvAuthManager.getPinToken(pinProtocol, platformKeyAgreementKey, pinHashEnc)
            }
            PinSubCommand.GET_PIN_UV_AUTH_TOKEN_USING_PIN_WITH_PERMISSIONS -> {
                logger.debug("Processing clientPIN getPinUvAuthTokenUsingPinWithPermissions sub-command (protocol={})", pinProtocol)
                pinUvAuthManager.getPinUvAuthTokenUsingPinWithPermissions(pinProtocol, platformKeyAgreementKey, pinHashEnc, permissions, rpId)
            }
            PinSubCommand.GET_PIN_UV_AUTH_TOKEN_USING_UV_WITH_PERMISSIONS -> {
                logger.debug("Processing clientPIN getPinUvAuthTokenUsingUvWithPermissions sub-command (protocol={})", pinProtocol)
                pinUvAuthManager.getPinUvAuthTokenUsingUvWithPermissions(pinProtocol, platformKeyAgreementKey, permissions, rpId)
            }
            PinSubCommand.GET_UV_RETRIES -> {
                logger.debug("Processing clientPIN getUVRetries sub-command")
                pinUvAuthManager.getUVRetries()
            }
        }
    }

    override fun createErrorResponse(statusCode: CtapStatusCode): AuthenticatorClientPINResponse {
        return AuthenticatorClientPINResponse(statusCode)
    }
}
