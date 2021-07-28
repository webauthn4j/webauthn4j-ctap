package com.webauthn4j.ctap.client

import com.webauthn4j.ctap.client.exception.CtapErrorException
import com.webauthn4j.ctap.client.transport.TransportAdaptor
import com.webauthn4j.ctap.core.data.*

/**
 * Provides low-level API corresponding CTAP commands
 */
class CtapAuthenticatorHandle(private val transportAdaptor: TransportAdaptor) {

    @Throws(CtapErrorException::class)
    suspend fun makeCredential(makeCredentialCommand: AuthenticatorMakeCredentialRequest): AuthenticatorMakeCredentialResponse {
        return invokeCommand(makeCredentialCommand)
    }

    @Throws(CtapErrorException::class)
    suspend fun getAssertion(getAssertionCommand: AuthenticatorGetAssertionRequest): AuthenticatorGetAssertionResponse {
        return invokeCommand(getAssertionCommand)
    }

    @JvmOverloads
    @Throws(CtapErrorException::class)
    suspend fun getInfo(getInfoCommand: AuthenticatorGetInfoRequest = AuthenticatorGetInfoRequest()): AuthenticatorGetInfoResponse {
        return invokeCommand(getInfoCommand)
    }


    @Throws(CtapErrorException::class)
    suspend fun clientPIN(clientPINCommand: AuthenticatorClientPINRequest): AuthenticatorClientPINResponse {
        require(!(clientPINCommand.keyAgreement != null && clientPINCommand.keyAgreement.privateKey != null)) { "keyAgreement COSEKey must not have private key." }
        return invokeCommand(clientPINCommand)
    }

    @JvmOverloads
    @Throws(CtapErrorException::class)
    suspend fun reset(resetCommand: AuthenticatorResetRequest = AuthenticatorResetRequest()): AuthenticatorResetResponse {
        return invokeCommand(resetCommand)
    }

    @JvmOverloads
    @Throws(CtapErrorException::class)
    suspend fun getNextAssertion(getNextAssertionCommand: AuthenticatorGetNextAssertionRequest = AuthenticatorGetNextAssertionRequest()): AuthenticatorGetNextAssertionResponse {
        return invokeCommand(getNextAssertionCommand)
    }

    @Throws(CtapErrorException::class)
    private suspend fun <TC : CtapRequest, TR : CtapResponse<TRD>, TRD : CtapResponseData?> invokeCommand(
        ctapCommand: TC
    ): TR {
        val ctapResponse: TR = transportAdaptor.send(ctapCommand)
        if (ctapResponse.statusCode == StatusCode.CTAP2_OK) {
            return ctapResponse
        } else {
            throw CtapErrorException(ctapResponse.statusCode)
        }
    }
}