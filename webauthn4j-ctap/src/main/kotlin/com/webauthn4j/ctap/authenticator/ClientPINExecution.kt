package com.webauthn4j.ctap.authenticator

import com.webauthn4j.ctap.core.data.AuthenticatorClientPINRequest
import com.webauthn4j.ctap.core.data.AuthenticatorClientPINResponse
import com.webauthn4j.ctap.core.data.PinSubCommand
import com.webauthn4j.ctap.core.data.CtapStatusCode
import org.slf4j.LoggerFactory

internal class ClientPINExecution(
    private val ctapAuthenticator: CtapAuthenticator,
    private val authenticatorClientPINCommand: AuthenticatorClientPINRequest
) : CtapCommandExecutionBase<AuthenticatorClientPINRequest, AuthenticatorClientPINResponse>(
    ctapAuthenticator,
    authenticatorClientPINCommand
) {
    private val logger = LoggerFactory.getLogger(ClientPINExecution::class.java)
    override val commandName: String = "ClientPIN"

    override suspend fun doExecute(): AuthenticatorClientPINResponse {
        val clientPINService = ctapAuthenticator.clientPINService
        val platformKeyAgreementKey = authenticatorClientPINCommand.keyAgreement
        val pinAuth = authenticatorClientPINCommand.pinAuth
        val newPinEnc = authenticatorClientPINCommand.newPinEnc
        val pinHashEnc = authenticatorClientPINCommand.pinHashEnc
        return when (authenticatorClientPINCommand.subCommand) {
            PinSubCommand.GET_PIN_RETRIES -> {
                logger.debug("Processing clientPIN getRetries sub-command")
                clientPINService.getPinRetries()
            }
            PinSubCommand.GET_KEY_AGREEMENT -> {
                logger.debug("Processing clientPIN getKeyAgreement sub-command")
                clientPINService.getKeyAgreement()
            }
            PinSubCommand.SET_PIN -> {
                logger.debug("Processing clientPIN setPIN sub-command")
                clientPINService.setPIN(platformKeyAgreementKey, pinAuth, newPinEnc)
            }
            PinSubCommand.CHANGE_PIN -> {
                logger.debug("Processing clientPIN changePIN sub-command")
                clientPINService.changePIN(platformKeyAgreementKey, pinAuth, newPinEnc, pinHashEnc)
            }
            PinSubCommand.GET_PIN_TOKEN -> {
                logger.debug("Processing clientPIN getPINToken sub-command")
                clientPINService.getPinToken(platformKeyAgreementKey, pinHashEnc)
            }
        }
    }

    override fun createErrorResponse(statusCode: CtapStatusCode): AuthenticatorClientPINResponse {
        return AuthenticatorClientPINResponse(statusCode)
    }
}