package com.webauthn4j.ctap.authenticator

import com.webauthn4j.ctap.authenticator.SignatureCalculator.calculate
import com.webauthn4j.ctap.core.data.AuthenticatorGetNextAssertionRequest
import com.webauthn4j.ctap.core.data.AuthenticatorGetNextAssertionResponse
import com.webauthn4j.ctap.core.data.AuthenticatorGetNextAssertionResponseData
import com.webauthn4j.ctap.core.data.StatusCode
import com.webauthn4j.data.PublicKeyCredentialDescriptor
import com.webauthn4j.data.PublicKeyCredentialType
import com.webauthn4j.data.PublicKeyCredentialUserEntity
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.nio.ByteBuffer

internal class GetNextAssertionExecution(
    private val ctapAuthenticator: CtapAuthenticator,
    authenticatorGetNextAssertionCommand: AuthenticatorGetNextAssertionRequest
) : CtapCommandExecutionBase<AuthenticatorGetNextAssertionRequest, AuthenticatorGetNextAssertionResponse>(
    ctapAuthenticator,
    authenticatorGetNextAssertionCommand
) {

    private val logger: Logger = LoggerFactory.getLogger(GetNextAssertionExecution::class.java)
    override val commandName: String = "GetNextAssertion"

    override suspend fun doExecute(): AuthenticatorGetNextAssertionResponse {

        //spec| Step1
        //spec| If authenticator does not remember any authenticatorGetAssertion parameters, return CTAP2_ERR_NOT_ALLOWED.
        val getAssertionSession = ctapAuthenticator.onGoingGetAssertionSession?: return AuthenticatorGetNextAssertionResponse(StatusCode.CTAP2_ERR_NOT_ALLOWED)

        //spec| Step2
        //spec| If the credentialCounter is equal to or greater than numberOfCredentials, return CTAP2_ERR_NOT_ALLOWED.
        val assertionObject: GetAssertionSession.AssertionObject
        try {
            assertionObject = getAssertionSession.nextAssertionObject()
        } catch (e: NoSuchElementException) {
            return AuthenticatorGetNextAssertionResponse(StatusCode.CTAP2_ERR_NOT_ALLOWED)
        }
        val userCredential = assertionObject.userCredential

        //spec| Step3
        //spec| If timer since the last call to authenticatorGetAssertion/authenticatorGetNextAssertion is greater than 30 seconds,
        //spec| discard the current authenticatorGetAssertion state and return CTAP2_ERR_NOT_ALLOWED.
        //spec| This step is optional if transport is done over NFC.
        if (getAssertionSession.isExpired()) {
            return AuthenticatorGetNextAssertionResponse(StatusCode.CTAP2_ERR_NOT_ALLOWED)
        }

        //spec| Step4
        //spec| Sign the clientDataHash along with authData with the credential
        //spec| using credentialCounter as index (e.g., credentials[n] assuming 0-based array), using the structure specified in [WebAuthn].
        val credential = PublicKeyCredentialDescriptor(
            PublicKeyCredentialType.PUBLIC_KEY,
            userCredential.credentialId,
            CtapAuthenticator.TRANSPORTS
        )
        val counter = userCredential.counter
        val authenticatorDataObject = AuthenticatorData(
            getAssertionSession.rpIdHash,
            assertionObject.flags,
            counter,
            assertionObject.extensions
        )
        val authData = ctapAuthenticator.authenticatorDataConverter.convert(authenticatorDataObject)
        val clientDataHash = getAssertionSession.clientDataHash
        val signedData = ByteBuffer.allocate(authData.size + clientDataHash.size).put(authData)
            .put(clientDataHash).array()
        val signature = calculate(
            userCredential.userCredentialKey.alg!!,
            userCredential.userCredentialKey.keyPair!!.private,
            signedData
        )
        val user = PublicKeyCredentialUserEntity(
            userCredential.userHandle,
            userCredential.username,
            userCredential.displayName
        )

        //spec| Step5
        //spec| Reset the timer. This step is optional if transport is done over NFC.
        getAssertionSession.resetTimer()

        //spec| Step6
        //spec| Increment credentialCounter.
        // This is done in `getAssertionSession.nextUserCredential();`
        val responseData =
            AuthenticatorGetNextAssertionResponseData(credential, authData, signature, user)
        return AuthenticatorGetNextAssertionResponse(StatusCode.CTAP2_OK, responseData)
    }

    override fun createErrorResponse(statusCode: StatusCode): AuthenticatorGetNextAssertionResponse {
        return AuthenticatorGetNextAssertionResponse(statusCode)
    }
}
