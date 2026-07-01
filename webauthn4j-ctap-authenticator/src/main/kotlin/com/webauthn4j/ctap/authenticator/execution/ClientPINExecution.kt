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
        val clientPINService = ctapAuthenticatorSession.clientPINService
        val pinProtocol = authenticatorClientPINRequest.pinProtocol
        val platformKeyAgreementKey = authenticatorClientPINRequest.keyAgreement
        val pinAuth = authenticatorClientPINRequest.pinAuth
        val newPinEnc = authenticatorClientPINRequest.newPinEnc
        val pinHashEnc = authenticatorClientPINRequest.pinHashEnc
        return when (authenticatorClientPINRequest.subCommand) {
            PinSubCommand.GET_PIN_RETRIES -> {
                logger.debug("Processing clientPIN getRetries sub-command")
                clientPINService.getPinRetries()
            }
            PinSubCommand.GET_KEY_AGREEMENT -> {
                logger.debug("Processing clientPIN getKeyAgreement sub-command (protocol={})", pinProtocol)
                clientPINService.getKeyAgreement(pinProtocol)
            }
            PinSubCommand.SET_PIN -> {
                logger.debug("Processing clientPIN setPIN sub-command (protocol={})", pinProtocol)
                clientPINService.setPIN(pinProtocol, platformKeyAgreementKey, pinAuth, newPinEnc)
            }
            PinSubCommand.CHANGE_PIN -> {
                logger.debug("Processing clientPIN changePIN sub-command (protocol={})", pinProtocol)
                clientPINService.changePIN(pinProtocol, platformKeyAgreementKey, pinAuth, newPinEnc, pinHashEnc)
            }
            PinSubCommand.GET_PIN_TOKEN -> {
                logger.debug("Processing clientPIN getPINToken sub-command (protocol={})", pinProtocol)
                clientPINService.getPinToken(pinProtocol, platformKeyAgreementKey, pinHashEnc)
            }
        }
    }

    override fun createErrorResponse(statusCode: CtapStatusCode): AuthenticatorClientPINResponse {
        return AuthenticatorClientPINResponse(statusCode)
    }
}
