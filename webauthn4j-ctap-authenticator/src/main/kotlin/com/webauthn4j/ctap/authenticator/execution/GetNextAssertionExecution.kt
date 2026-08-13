package com.webauthn4j.ctap.authenticator.execution

import com.webauthn4j.ctap.authenticator.CtapAuthenticatorSession
import com.webauthn4j.ctap.authenticator.SignatureCalculator.calculate
import com.webauthn4j.ctap.authenticator.data.credential.ResidentUserCredential
import com.webauthn4j.ctap.authenticator.data.credential.UserCredential
import com.webauthn4j.ctap.authenticator.store.StoreFullException
import com.webauthn4j.ctap.core.data.AuthenticatorGetNextAssertionRequest
import com.webauthn4j.ctap.core.data.AuthenticatorGetNextAssertionResponse
import com.webauthn4j.ctap.core.data.AuthenticatorGetNextAssertionResponseData
import com.webauthn4j.ctap.core.data.CtapStatusCode
import com.webauthn4j.data.PublicKeyCredentialDescriptor
import com.webauthn4j.data.PublicKeyCredentialType
import com.webauthn4j.data.PublicKeyCredentialUserEntity
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData
import java.nio.ByteBuffer

/**
 * GetNextAssertion command execution
 *
 * @see <a href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorGetNextAssertion">CTAP 2.3 §6.3 authenticatorGetNextAssertion</a>
 */
internal class GetNextAssertionExecution(
    private val ctapAuthenticatorSession: CtapAuthenticatorSession,
    authenticatorGetNextAssertionRequest: AuthenticatorGetNextAssertionRequest
) : CtapCommandExecutionBase<AuthenticatorGetNextAssertionRequest, AuthenticatorGetNextAssertionResponse>(
    ctapAuthenticatorSession,
    authenticatorGetNextAssertionRequest
) {

    override val commandName: String = "GetNextAssertion"

    override suspend fun validate() {
        // nop
    }

    //spec| When this command is received, the authenticator performs the following procedure:
    //spec| Step 1. If the authenticator does not remember any authenticatorGetAssertion parameters, return CTAP2_ERR_NOT_ALLOWED.
    //spec| Step 2. If the credentialCounter is equal to or greater than numberOfCredentials, return CTAP2_ERR_NOT_ALLOWED.
    //spec| Step 3. If timer since the last call to authenticatorGetAssertion/authenticatorGetNextAssertion is greater than 30 seconds,
    //spec| discard the current authenticatorGetAssertion state and return CTAP2_ERR_NOT_ALLOWED.
    //spec| This step is OPTIONAL if transport is done over NFC.
    //spec| Step 4. Select the credential indexed by credentialCounter. (I.e. credentials[n] assuming a zero-based array.)
    //spec| Step 5. Update the response to include the selected credential's publicKeyCredentialUserEntity information.
    //spec| User identifiable information (name, DisplayName, icon) inside the publicKeyCredentialUserEntity MUST NOT be returned
    //spec| if user verification was not done by the authenticator in the original authenticatorGetAssertion call.
    //spec| Step 6. Sign the clientDataHash along with authData with the selected credential, using the structure specified in [WebAuthn].
    //spec| Step 7. Reset the timer. This step is OPTIONAL if transport is done over NFC.
    //spec| Step 8. Increment credentialCounter.
    //
    // @see https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorGetNextAssertion
    override suspend fun doExecute(): AuthenticatorGetNextAssertionResponse {

        //spec| Step 1. If the authenticator does not remember any authenticatorGetAssertion parameters, return CTAP2_ERR_NOT_ALLOWED.
        val getAssertionSession = ctapAuthenticatorSession.onGoingGetAssertionSession
            ?: throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_NOT_ALLOWED)

        //spec| Step 2. If the credentialCounter is equal to or greater than numberOfCredentials, return CTAP2_ERR_NOT_ALLOWED.
        if (!getAssertionSession.hasNext()) {
            throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_NOT_ALLOWED)
        }

        //spec| Step 3. If timer since the last call to authenticatorGetAssertion/authenticatorGetNextAssertion is greater than 30 seconds,
        //spec| discard the current authenticatorGetAssertion state and return CTAP2_ERR_NOT_ALLOWED.
        //spec| This step is OPTIONAL if transport is done over NFC.
        if (getAssertionSession.isExpired()) {
            ctapAuthenticatorSession.onGoingGetAssertionSession = null
            throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_NOT_ALLOWED)
        }

        //spec| Step 4. Select the credential indexed by credentialCounter. (I.e. credentials[n] assuming a zero-based array.)
        val assertionObject = getAssertionSession.currentAssertionObject()
        val credential = assertionObject.credential
        val descriptor = PublicKeyCredentialDescriptor(
            PublicKeyCredentialType.PUBLIC_KEY,
            credential.credentialId,
            ctapAuthenticatorSession.transports
        )

        //spec| Step 5. Update the response to include the selected credential's publicKeyCredentialUserEntity information.
        //spec| User identifiable information (name, DisplayName, icon) inside the publicKeyCredentialUserEntity MUST NOT be returned
        //spec| if user verification was not done by the authenticator in the original authenticatorGetAssertion call.
        val user = when (credential) {
            is UserCredential -> when (assertionObject.maskUserIdentifiableInfo) {
                true -> PublicKeyCredentialUserEntity(
                    credential.userHandle,
                    "",
                    ""
                )
                false -> PublicKeyCredentialUserEntity(
                    credential.userHandle,
                    credential.username ?: "",
                    credential.displayName ?: ""
                )
            }
            else -> null
        }

        //spec| Step 6. Sign the clientDataHash along with authData with the selected credential, using the structure specified in [WebAuthn].
        val counter = credential.counter
        val authenticatorDataObject = AuthenticatorData(
            assertionObject.credential.rpIdHash,
            assertionObject.flags,
            counter,
            assertionObject.extensions
        )
        val authData = ctapAuthenticatorSession.authenticatorDataConverter.convert(authenticatorDataObject)
        val clientDataHash = getAssertionSession.clientDataHash
        val signedData = ByteBuffer.allocate(authData.size + clientDataHash.size).put(authData)
            .put(clientDataHash).array()
        val signature = calculate(
            credential.credentialKey.alg!!,
            credential.credentialKey.keyPair!!.private,
            signedData
        )

        // Update credential counter (same as GetAssertionExecution Step 13)
        if (credential is ResidentUserCredential) {
            credential.counter = counter + 1
            try {
                ctapAuthenticatorSession.authenticatorPropertyStore.saveUserCredential(credential)
            } catch (e: StoreFullException) {
                throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_KEY_STORE_FULL, e)
            }
        }

        //spec| Step 7. Reset the timer. This step is OPTIONAL if transport is done over NFC.
        getAssertionSession.resetTimer()

        //spec| Step 8. Increment credentialCounter.
        getAssertionSession.incrementCredentialCounter()

        val responseData =
            AuthenticatorGetNextAssertionResponseData(descriptor, authData, signature, user)
        return AuthenticatorGetNextAssertionResponse(CtapStatusCode.CTAP2_OK, responseData)
    }

    override fun createErrorResponse(statusCode: CtapStatusCode): AuthenticatorGetNextAssertionResponse {
        return AuthenticatorGetNextAssertionResponse(statusCode)
    }
}
