package com.webauthn4j.ctap.authenticator.execution

import com.webauthn4j.ctap.authenticator.CtapAuthenticatorSession
import com.webauthn4j.ctap.authenticator.MakeCredentialConsentRequest
import com.webauthn4j.ctap.authenticator.U2FKeyEnvelope
import com.webauthn4j.ctap.authenticator.attestation.FIDOU2FAttestationStatementRequest
import com.webauthn4j.ctap.core.data.U2FRegistrationRequest
import com.webauthn4j.ctap.core.data.U2FRegistrationResponse
import com.webauthn4j.ctap.core.data.U2FStatusCode
import com.webauthn4j.ctap.core.util.internal.CipherUtil
import com.webauthn4j.ctap.core.validator.U2FRegistrationRequestValidator
import com.webauthn4j.data.attestation.authenticator.EC2COSEKey
import com.webauthn4j.util.ECUtil
import org.slf4j.LoggerFactory
import java.security.interfaces.ECPublicKey
import java.time.Instant

class U2FRegisterExecution(
    private val ctapAuthenticatorSession: CtapAuthenticatorSession,
    private val u2FRegistrationRequest: U2FRegistrationRequest
) {

    private val logger = LoggerFactory.getLogger(U2FAuthenticationExecution::class.java)
    private val u2fRegistrationRequestValidator = U2FRegistrationRequestValidator()

    @Suppress("RedundantSuspendModifier")
    suspend fun validate() {
        u2fRegistrationRequestValidator.validate(u2FRegistrationRequest)
    }

    suspend fun execute(): U2FRegistrationResponse {
        logger.info("U2F Registration Command {}", u2FRegistrationRequest.toString())

        val response: U2FRegistrationResponse

        validate()
        try {
            response = doExecute()
        } catch (e: U2FCommandExecutionException) {
            throw e
        } catch (e: java.lang.RuntimeException) {
            logger.error("Unknown error occurred while processing U2F Registration Command.", e)
            ctapAuthenticatorSession.reportException(e)
            throw U2FCommandExecutionException(U2FStatusCode.WRONG_DATA, e)
        }

        logger.info("U2F Registration Response {}", response.toString())
        return response
    }

    suspend fun doExecute(): U2FRegistrationResponse {
        val keyPair = ECUtil.createKeyPair()
        val encryptionKey = ctapAuthenticatorSession.authenticatorPropertyStore.loadEncryptionKey()
        val encryptionIV = ctapAuthenticatorSession.authenticatorPropertyStore.loadEncryptionIV()

        // As Android doesn't support extended APDU, keyHandle must be small enough to fit in one short APDU.
        val envelope = U2FKeyEnvelope.create(
            EC2COSEKey.create(keyPair),
            u2FRegistrationRequest.applicationParameter,
            Instant.now()
        )
        val data = ctapAuthenticatorSession.objectConverter.cborConverter.writeValueAsBytes(envelope)

        val userPresenceResult = requestUserPresence(u2FRegistrationRequest.applicationParameter)
        if (!userPresenceResult) {
            throw U2FCommandExecutionException(U2FStatusCode.CONDITION_NOT_SATISFIED)
        }

        val reservedByte = 0x05.toByte()
        val userPublicKey = keyPair.public as ECPublicKey
        val keyHandle: ByteArray =
            CipherUtil.encryptWithAESCBCPKCS5Padding(data, encryptionKey, encryptionIV)
        val attestationStatementRequest = FIDOU2FAttestationStatementRequest(
            keyPair,
            keyHandle,
            u2FRegistrationRequest.applicationParameter,
            u2FRegistrationRequest.challengeParameter
        )
        val attestationStatement =
            ctapAuthenticatorSession.fidoU2FBasicAttestationStatementGenerator.generate(
                attestationStatementRequest
            )
        return U2FRegistrationResponse(
            reservedByte,
            userPublicKey,
            keyHandle,
            attestationStatement.x5c.endEntityAttestationCertificate,
            attestationStatement.sig
        )
    }

    private suspend fun requestUserPresence(applicationParameter: ByteArray): Boolean {
        val makeCredentialConsentRequest = MakeCredentialConsentRequest(
            applicationParameter,
            null,
            isUserPresenceRequired = true,
            isUserVerificationRequired = false
        )
        return ctapAuthenticatorSession.makeCredentialConsentRequestHandler.onMakeCredentialConsentRequested(makeCredentialConsentRequest)
    }

}