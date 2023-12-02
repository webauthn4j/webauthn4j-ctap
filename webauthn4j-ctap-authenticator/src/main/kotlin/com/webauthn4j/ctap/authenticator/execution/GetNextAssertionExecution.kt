package com.webauthn4j.ctap.authenticator.execution

import com.webauthn4j.ctap.authenticator.Connection
import com.webauthn4j.ctap.authenticator.CtapAuthenticator
import com.webauthn4j.ctap.authenticator.GetAssertionSession
import com.webauthn4j.ctap.authenticator.SignatureCalculator.calculate
import com.webauthn4j.ctap.authenticator.data.credential.UserCredential
import com.webauthn4j.ctap.core.data.AuthenticatorGetNextAssertionRequest
import com.webauthn4j.ctap.core.data.AuthenticatorGetNextAssertionResponse
import com.webauthn4j.ctap.core.data.AuthenticatorGetNextAssertionResponseData
import com.webauthn4j.ctap.core.data.CtapPublicKeyCredentialUserEntity
import com.webauthn4j.ctap.core.data.CtapStatusCode
import com.webauthn4j.data.PublicKeyCredentialDescriptor
import com.webauthn4j.data.PublicKeyCredentialType
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.nio.ByteBuffer

/**
 * GetNextAssertion command execution
 */
internal class GetNextAssertionExecution(
    private val connection: Connection,
    authenticatorGetNextAssertionRequest: AuthenticatorGetNextAssertionRequest
) : CtapCommandExecutionBase<AuthenticatorGetNextAssertionRequest, AuthenticatorGetNextAssertionResponse>(
    connection,
    authenticatorGetNextAssertionRequest
) {

    private val logger: Logger = LoggerFactory.getLogger(GetNextAssertionExecution::class.java)
    override val commandName: String = "GetNextAssertion"

    override suspend fun validate() {
        // nop
    }

    override suspend fun doExecute(): AuthenticatorGetNextAssertionResponse {

        //spec| Step1
        //spec| If authenticator does not remember any authenticatorGetAssertion parameters, return CTAP2_ERR_NOT_ALLOWED.
        val getAssertionSession = connection.onGoingGetAssertionSession?: return AuthenticatorGetNextAssertionResponse(CtapStatusCode.CTAP2_ERR_NOT_ALLOWED)

        //spec| Step2
        //spec| If the credentialCounter is equal to or greater than numberOfCredentials, return CTAP2_ERR_NOT_ALLOWED.
        val assertionObject: GetAssertionSession.AssertionObject
        try {
            assertionObject = getAssertionSession.nextAssertionObject()
        } catch (e: NoSuchElementException) {
            return AuthenticatorGetNextAssertionResponse(CtapStatusCode.CTAP2_ERR_NOT_ALLOWED)
        }
        val credential = assertionObject.credential

        //spec| Step3
        //spec| If timer since the last call to authenticatorGetAssertion/authenticatorGetNextAssertion is greater than 30 seconds,
        //spec| discard the current authenticatorGetAssertion state and return CTAP2_ERR_NOT_ALLOWED.
        //spec| This step is optional if transport is done over NFC.
        if (getAssertionSession.isExpired()) {
            return AuthenticatorGetNextAssertionResponse(CtapStatusCode.CTAP2_ERR_NOT_ALLOWED)
        }

        //spec| Step4
        //spec| Sign the clientDataHash along with authData with the credential
        //spec| using credentialCounter as index (e.g., credentials[n] assuming 0-based array), using the structure specified in [WebAuthn].
        val descriptor = PublicKeyCredentialDescriptor(
            PublicKeyCredentialType.PUBLIC_KEY,
            credential.credentialId,
            CtapAuthenticator.TRANSPORTS
        )
        val counter = credential.counter
        val authenticatorDataObject = AuthenticatorData(
            assertionObject.credential.rpIdHash,
            assertionObject.flags,
            counter,
            assertionObject.extensions
        )
        val authData = connection.authenticatorDataConverter.convert(authenticatorDataObject)
        val clientDataHash = getAssertionSession.clientDataHash
        val signedData = ByteBuffer.allocate(authData.size + clientDataHash.size).put(authData)
            .put(clientDataHash).array()
        val signature = calculate(
            credential.credentialKey.alg!!,
            credential.credentialKey.keyPair!!.private,
            signedData
        )
        val user = when (credential) {
            is UserCredential -> when(assertionObject.maskUserIdentifiableInfo){
                true -> CtapPublicKeyCredentialUserEntity(
                    credential.userHandle,
                    null,
                    null,
                    null
                )
                false -> CtapPublicKeyCredentialUserEntity(
                    credential.userHandle,
                    credential.username,
                    credential.displayName,
                    credential.icon
                )
            }
            else -> null
        }

        //spec| Step5
        //spec| Reset the timer. This step is optional if transport is done over NFC.
        getAssertionSession.resetTimer()

        //spec| Step6
        //spec| Increment credentialCounter.
        // This is done in `getAssertionSession.nextUserCredential();`
        val responseData =
            AuthenticatorGetNextAssertionResponseData(descriptor, authData, signature, user)
        return AuthenticatorGetNextAssertionResponse(CtapStatusCode.CTAP2_OK, responseData)
    }

    override fun createErrorResponse(statusCode: CtapStatusCode): AuthenticatorGetNextAssertionResponse {
        return AuthenticatorGetNextAssertionResponse(statusCode)
    }
}
