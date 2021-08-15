package com.webauthn4j.ctap.authenticator

import com.webauthn4j.ctap.authenticator.attestation.FIDOU2FAttestationStatementRequest
import com.webauthn4j.ctap.authenticator.exception.U2FCommandExecutionException
import com.webauthn4j.ctap.core.data.U2FRegistrationRequest
import com.webauthn4j.ctap.core.data.U2FRegistrationResponse
import com.webauthn4j.ctap.core.data.U2FStatusCode
import com.webauthn4j.ctap.core.util.internal.CipherUtil
import com.webauthn4j.data.attestation.authenticator.EC2COSEKey
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier
import com.webauthn4j.util.ECUtil
import org.slf4j.LoggerFactory
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.time.Instant

class U2FRegisterExecution(private val ctapAuthenticator: CtapAuthenticator, private val request: U2FRegistrationRequest) {

    private val logger = LoggerFactory.getLogger(U2FAuthenticationExecution::class.java)

    suspend fun execute(): U2FRegistrationResponse {
        logger.info("U2F Registration Command {}", request.toString())

        val keyPair = ECUtil.createKeyPair()
        val encryptionKey = ctapAuthenticator.authenticatorPropertyStore.loadEncryptionKey()
        val encryptionIV = ctapAuthenticator.authenticatorPropertyStore.loadEncryptionIV()

        // As Android doesn't support extended APDU, keyHandle must be small enough to fit in one short APDU.
        val envelope = U2FKeyEnvelope(EC2COSEKey.create(keyPair.private as ECPrivateKey), request.applicationParameter, Instant.now())
        val data = ctapAuthenticator.objectConverter.cborConverter.writeValueAsBytes(envelope)

        val userPresenceResult = requestUserPresence(request.applicationParameter)
        if(!userPresenceResult){
            throw U2FCommandExecutionException(U2FStatusCode.CONDITION_NOT_SATISFIED)
        }

        val reservedByte = 0x05.toByte()
        val userPublicKey = keyPair.public as ECPublicKey
        val keyHandle: ByteArray = CipherUtil.encryptWithAESCBCPKCS5Padding(data, encryptionKey, encryptionIV)
        val attestationStatementRequest = FIDOU2FAttestationStatementRequest(keyPair.public as ECPublicKey, keyHandle, request.applicationParameter, request.challengeParameter)
        val attestationStatement = ctapAuthenticator.fidoU2FAttestationStatementGenerator.generate(attestationStatementRequest)
        val response = U2FRegistrationResponse(reservedByte, userPublicKey, keyHandle, attestationStatement.x5c.endEntityAttestationCertificate, attestationStatement.sig)
        logger.info("U2F Registration Response {}", response.toString())
        return response
    }

    private suspend fun requestUserPresence(applicationParameter: ByteArray): Boolean{
        val options = MakeCredentialConsentOptions(applicationParameter,null, isUserPresence = true, isUserVerification = false)
        return ctapAuthenticator.userConsentHandler.consentMakeCredential(options)
    }

}