package com.webauthn4j.ctap.authenticator

import com.webauthn4j.ctap.authenticator.exception.CtapCommandExecutionException
import com.webauthn4j.ctap.authenticator.exception.U2FCommandExecutionException
import com.webauthn4j.ctap.authenticator.settings.UserPresenceSetting
import com.webauthn4j.ctap.core.data.CtapStatusCode
import com.webauthn4j.ctap.core.data.U2FAuthenticationRequest
import com.webauthn4j.ctap.core.data.U2FAuthenticationResponse
import com.webauthn4j.ctap.core.data.U2FStatusCode
import com.webauthn4j.ctap.core.data.nfc.ResponseAPDU
import com.webauthn4j.ctap.core.util.internal.CipherUtil
import com.webauthn4j.ctap.core.util.internal.HexUtil
import com.webauthn4j.ctap.core.validator.U2FAuthenticationRequestValidator
import com.webauthn4j.data.SignatureAlgorithm
import org.slf4j.LoggerFactory
import java.nio.ByteBuffer

class U2FAuthenticationExecution(
    private val ctapAuthenticator: CtapAuthenticator,
    private val u2fAuthenticationRequest: U2FAuthenticationRequest) {

    private val logger = LoggerFactory.getLogger(U2FAuthenticationExecution::class.java)
    private val u2fAuthenticationRequestValidator = U2FAuthenticationRequestValidator()

    suspend fun validate() {
        u2fAuthenticationRequestValidator.validate(u2fAuthenticationRequest)
    }

    suspend fun execute(): U2FAuthenticationResponse {
        logger.info("U2F Authentication Command {}", u2fAuthenticationRequest.toString())

        val response: U2FAuthenticationResponse

        validate()
        try{
            response = doExecute()
        }
        catch (e: U2FCommandExecutionException){
            throw e
        }
        catch (e: java.lang.RuntimeException){
            logger.error("Unknown error occurred while processing U2F Authentication Command.", e)
            ctapAuthenticator.reportException(e)
            throw U2FCommandExecutionException(U2FStatusCode.WRONG_DATA, e)
        }
        logger.info("U2F Authentication Response {}", response.toString())
        return response
    }

    suspend fun doExecute(): U2FAuthenticationResponse {
        val encryptionKey = ctapAuthenticator.authenticatorPropertyStore.loadEncryptionKey()
        val encryptionIV = ctapAuthenticator.authenticatorPropertyStore.loadEncryptionIV()

        //spec| If the key handle was not created by this U2F token, or if it was created for a different application parameter,
        //spec| the token must respond with an authentication response message:error:bad-key-handle.
        val envelope: U2FKeyEnvelope
        try {
            val decrypted = CipherUtil.decryptWithAESCBCPKCS5Padding(
                u2fAuthenticationRequest.keyHandle,
                encryptionKey,
                encryptionIV
            )
            envelope = ctapAuthenticator.objectConverter.cborConverter.readValue(
                decrypted,
                U2FKeyEnvelope::class.java
            )!!
        } catch (e: RuntimeException) {
            throw U2FCommandExecutionException(U2FStatusCode.WRONG_DATA, e)
        }
        val decodedApplicationParameter = HexUtil.encodeToString(envelope.applicationParameter)!!
        val requestApplicationParameter= HexUtil.encodeToString(u2fAuthenticationRequest.applicationParameter)!!
        if (decodedApplicationParameter != requestApplicationParameter) {
            throw U2FCommandExecutionException(U2FStatusCode.WRONG_DATA)
        }

        val userPresencePlan: Boolean
        when (u2fAuthenticationRequest.controlByte) {
            0x07.toByte() -> { //check only
                //spec| if the control byte is set to 0x07 by the FIDO Client,
                //spec| the U2F token is supposed to simply check whether the provided key handle was originally created by this token,
                //spec| and whether it was created for the provided application parameter.
                //spec| If so, the U2F token must respond with an authentication response message:error:test-of-user-presence-required
                //spec| (note that despite the name this signals a success condition).
                throw U2FCommandExecutionException(U2FStatusCode.CONDITION_NOT_SATISFIED)
            }
            0x03.toByte() -> { //enforce user presence and sign
                //spec| If the FIDO client sets the control byte to 0x03,
                //spec| then the U2F token is supposed to perform a real signature and respond with either an authentication response message:success
                //spec| or an appropriate error response (see below).
                //spec| The signature should only be provided if user presence could be validated.
                userPresencePlan =
                    ctapAuthenticator.userPresenceSetting == UserPresenceSetting.SUPPORTED
            }
            0x08.toByte() -> { //don't enforce user presence and sign
                userPresencePlan = false
            }
            else -> {
                throw U2FCommandExecutionException(U2FStatusCode.INS_NOT_SUPPORTED)
            }
        }

        @Suppress("MoveVariableDeclarationIntoWhen")
        val userPresenceResult =
            requestUserPresence(u2fAuthenticationRequest.applicationParameter, userPresencePlan)

        val userPresence = when (userPresenceResult) {
            true -> 0x01.toByte()
            false -> 0x00.toByte()
        }
        val counter = ctapAuthenticator.authenticatorPropertyStore.loadDeviceWideCounter() + 1u
        ctapAuthenticator.authenticatorPropertyStore.saveDeviceWideCounter(counter)
        val signedData =
            ByteBuffer.allocate(32 + 1 + 4 + 32).put(u2fAuthenticationRequest.applicationParameter)
                .put(userPresence).putInt(counter.toInt())
                .put(u2fAuthenticationRequest.challengeParameter).array()
        val privateKey = envelope.keyPair.privateKey!!
        val signature =
            SignatureCalculator.calculate(SignatureAlgorithm.ES256, privateKey, signedData)

        return U2FAuthenticationResponse(userPresence, counter, signature)
    }

    private suspend fun requestUserPresence(applicationParameter: ByteArray, userPresencePlan: Boolean): Boolean{
        val options = GetAssertionConsentOptions(applicationParameter, userPresencePlan, false)
        return ctapAuthenticator.userConsentHandler.consentGetAssertion(options)
    }
}