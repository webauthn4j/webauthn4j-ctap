package com.webauthn4j.ctap.authenticator

import com.fasterxml.jackson.core.type.TypeReference
import com.webauthn4j.ctap.authenticator.SignatureCalculator.calculate
import com.webauthn4j.ctap.authenticator.event.GetAssertionEvent
import com.webauthn4j.ctap.authenticator.exception.CtapCommandExecutionException
import com.webauthn4j.ctap.authenticator.exception.StoreFullException
import com.webauthn4j.ctap.authenticator.extension.AuthenticationExtensionContext
import com.webauthn4j.ctap.authenticator.extension.AuthenticationExtensionProcessor
import com.webauthn4j.ctap.authenticator.settings.CredentialSelectorSetting
import com.webauthn4j.ctap.authenticator.settings.UserPresenceSetting
import com.webauthn4j.ctap.authenticator.settings.UserVerificationSetting
import com.webauthn4j.ctap.authenticator.store.*
import com.webauthn4j.ctap.core.data.*
import com.webauthn4j.ctap.core.util.internal.BooleanUtil
import com.webauthn4j.ctap.core.util.internal.CipherUtil
import com.webauthn4j.ctap.core.util.internal.HexUtil
import com.webauthn4j.data.PublicKeyCredentialDescriptor
import com.webauthn4j.data.PublicKeyCredentialType
import com.webauthn4j.data.PublicKeyCredentialUserEntity
import com.webauthn4j.data.SignatureAlgorithm
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionAuthenticatorInput
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorInputs
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorOutputs
import com.webauthn4j.util.MessageDigestUtil
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.nio.ByteBuffer
import java.time.Instant
import kotlin.collections.ArrayList
import kotlin.experimental.or

@Suppress("ConvertSecondaryConstructorToPrimary")
internal class GetAssertionExecution :
    CtapCommandExecutionBase<AuthenticatorGetAssertionRequest, AuthenticatorGetAssertionResponse> {

    override val commandName: String = "GetAssertion"

    @Suppress("JoinDeclarationAndAssignment")
    private val ctapAuthenticator: CtapAuthenticator
    private val authenticatorGetAssertionCommand: AuthenticatorGetAssertionRequest

    private val logger: Logger = LoggerFactory.getLogger(GetAssertionExecution::class.java)
    private val authenticatorPropertyStore: AuthenticatorPropertyStore

    //Command properties
    private val authenticatorGetAssertionRequest: AuthenticatorGetAssertionRequest
    private val rpId: String
    private val clientDataHash: ByteArray
    private val allowList: List<PublicKeyCredentialDescriptor>?
    private val authenticationExtensionsAuthenticatorInputs: AuthenticationExtensionsAuthenticatorInputs<AuthenticationExtensionAuthenticatorInput>?
    private val options: AuthenticatorGetAssertionRequest.Options?
    private val pinAuth: ByteArray?
    private val pinProtocol: PinProtocolVersion?

    // initialized in Step1
    private lateinit var userCredentials: List<UserCredential>
    // initialized in Step6
    private lateinit var assertionObjects: List<GetAssertionSession.AssertionObject>
    // initialized in Step10
    private lateinit var onGoingGetAssertionSession: GetAssertionSession

    private var userVerificationPlan = false
    private var userPresencePlan = false
    private var userVerificationResult = false
    private var userPresenceResult = false


    constructor(
        ctapAuthenticator: CtapAuthenticator,
        authenticatorGetAssertionRequest: AuthenticatorGetAssertionRequest
    ) : super(ctapAuthenticator, authenticatorGetAssertionRequest) {
        this.authenticatorGetAssertionRequest = authenticatorGetAssertionRequest
        this.ctapAuthenticator = ctapAuthenticator
        this.authenticatorGetAssertionCommand = authenticatorGetAssertionRequest
        this.authenticatorPropertyStore = ctapAuthenticator.authenticatorPropertyStore

        // command properties initialization and validation
        this.rpId = authenticatorGetAssertionRequest.rpId
        this.clientDataHash = authenticatorGetAssertionRequest.clientDataHash
        this.allowList = authenticatorGetAssertionRequest.allowList
        this.authenticationExtensionsAuthenticatorInputs = authenticatorGetAssertionRequest.extensions
        this.options = authenticatorGetAssertionRequest.options
        this.pinAuth = authenticatorGetAssertionRequest.pinAuth
        this.pinProtocol = authenticatorGetAssertionRequest.pinProtocol
    }

    override suspend fun doExecute(): AuthenticatorGetAssertionResponse {
        execStep1LoadEligibleUserCredentials()
        execStep2VerifyClientPIN()
        execStep3ValidatePinProtocol()
        execStep4SetUVWhenClientPinHasBeenSet()
        execStep5ProcessOptions()
        execStep6ProcessExtensions()
        execStep7RequestUserConsent()
        execStep8CheckUserCredentialCandidatesExistence()
        execStep9SortUserCredentials()
        execStep10PrepareGetAssertionSession()
        execStep11SelectUserCredentialIfCredentialSelectorIsAuthenticator()
        val response = execStep12SignClientDataHashAndAuthData()
        val userCredentials = onGoingGetAssertionSession.assertionObjects.map {
            GetAssertionEvent.UserCredential(
                it.userCredential.username,
                it.userCredential.displayName
            )
        }
        val rpName = onGoingGetAssertionSession.assertionObjects.first().userCredential.rpName
        val event = GetAssertionEvent(Instant.now(), rpId, rpName, userCredentials, mapOf())
        ctapAuthenticator.publishEvent(event)
        return response
    }


    override fun createErrorResponse(statusCode: CtapStatusCode): AuthenticatorGetAssertionResponse {
        return AuthenticatorGetAssertionResponse(statusCode)
    }

    //spec| Step1
    //spec| Locate all userCredentials that are eligible for retrieval under the specified criteria:
    //spec| - If an allowList is present and is non-empty, locate all denoted userCredentials present on this authenticator and bound to the specified rpId.
    //spec| - If an allowList is not present, locate all userCredentials that are present on this authenticator and bound to the specified rpId.
    //spec| - Let numberOfCredentials be the number of userCredentials found.
    private fun execStep1LoadEligibleUserCredentials() {
        val rpId = rpId
        userCredentials = if (allowList != null && allowList.isNotEmpty()) {
            val storedCredentials = authenticatorPropertyStore.loadUserCredentials(rpId)
                .filter {
                    allowList.any { allowed: PublicKeyCredentialDescriptor ->
                        it.credentialId.contentEquals(
                            allowed.id
                        )
                    }
                }
            val derivedCredentials = allowList.mapNotNull(this::deriveUserCredential).filter { it.rpId == rpId }
            val result: MutableList<UserCredential> = ArrayList()
            result.addAll(storedCredentials)
            result.addAll(derivedCredentials)
            result
        } else {
            ArrayList<UserCredential>(
                authenticatorPropertyStore.loadUserCredentials(
                    rpId
                )
            )
        }
    }

    private fun deriveUserCredential(descriptor: PublicKeyCredentialDescriptor): UserCredential? {
        val credentialSourceEncryptionKey = authenticatorPropertyStore.loadEncryptionKey()
        val credentialSourceEncryptionIV = authenticatorPropertyStore.loadEncryptionIV()
        val decrypted : ByteArray
        try{
            decrypted = CipherUtil.decryptWithAESCBCPKCS5Padding(
                descriptor.id,
                credentialSourceEncryptionKey,
                credentialSourceEncryptionIV
            )!!
        }
        catch (e: RuntimeException){
            logger.debug(
                "Skipped credentialId: %s as it doesn't contain valid NonResidentUserCredentialSource.".format(
                    HexUtil.encodeToString(descriptor.id)
                )
            )
            return null
        }
        try {
            val nonResidentUserCredentialEnvelope =
                ctapAuthenticator.objectConverter.cborConverter.readValue(
                    decrypted,
                    object : TypeReference<NonResidentUserCredentialSource>() {})!!
            return NonResidentUserCredential(
                descriptor.id,
                nonResidentUserCredentialEnvelope.userCredentialKey,
                nonResidentUserCredentialEnvelope.userHandle,
                nonResidentUserCredentialEnvelope.username,
                nonResidentUserCredentialEnvelope.displayName,
                nonResidentUserCredentialEnvelope.rpId,
                nonResidentUserCredentialEnvelope.rpName,
                nonResidentUserCredentialEnvelope.createdAt,
                nonResidentUserCredentialEnvelope.otherUI,
                nonResidentUserCredentialEnvelope.details
            )
        } catch (e: RuntimeException) {
            logger.trace("Failed to load NonResidentUserCredentialSource from credentialId", e)
        }
        try{
            val u2fKeyEnvelope =
                ctapAuthenticator.objectConverter.cborConverter.readValue(
                    decrypted,
                    object : TypeReference<U2FKeyEnvelope>() {})!!

            val expectedRpIdHash = MessageDigestUtil.createSHA256().digest(rpId.toByteArray())
            if(!descriptor.id.contentEquals(expectedRpIdHash)){
                return null
            }
            val key = NonResidentUserCredentialKey(SignatureAlgorithm.ES256, u2fKeyEnvelope.privateKey.publicKey!!, u2fKeyEnvelope.privateKey.privateKey!!)
            return NonResidentUserCredential(
                descriptor.id,
                key,
                null,
                "unknown (U2F)",
                "unknown (U2F)",
                rpId,
                "unknown (U2F)",
                u2fKeyEnvelope.createdAt,
                null,
                emptyMap()
            )
        }
        catch (e: RuntimeException){
            logger.trace("Failed to load U2FKeyEnvelope from credentialId", e)
        }
        return null
    }

    //spec| Step2
    //spec| If pinAuth parameter is present and pinProtocol is 1,
    //spec| verify it by matching it against first 16 bytes of HMAC-SHA-256 of clientDataHash parameter
    //spec| using pinToken: HMAC-SHA-256(pinToken, clientDataHash).
    private fun execStep2VerifyClientPIN() {
        if (pinAuth != null && pinProtocol == PinProtocolVersion.VERSION_1) {
            val clientDataHash = clientDataHash
            val pinAuth = pinAuth
            ctapAuthenticator.clientPINService.validatePINAuth(pinAuth, clientDataHash)
            userVerificationResult = true
        }
    }

    //spec| Step3
    //spec| If pinAuth parameter is present and the pinProtocol is not supported, return CTAP2_ERR_PIN_AUTH_INVALID.
    private fun execStep3ValidatePinProtocol() {
        if (pinAuth != null && pinProtocol != PinProtocolVersion.VERSION_1) {
            throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_PIN_AUTH_INVALID)
        }
    }

    //spec| Step4
    //spec| If pinAuth parameter is not present and clientPin has been set on the authenticator,
    //spec| set the "uv" bit to 0 in the response.
    private fun execStep4SetUVWhenClientPinHasBeenSet() {
        if (pinAuth == null && ctapAuthenticator.clientPINService.isClientPINReady) {
            userVerificationResult = false
        }
    }

    //spec| Step5
    //spec| If the options parameter is present, process all the options.
    //spec| If the option is known but not supported, terminate this procedure and return CTAP2_ERR_UNSUPPORTED_OPTION.
    //spec| If the option is known but not valid for this command, terminate this procedure and return CTAP2_ERR_INVALID_OPTION.
    //spec| Ignore any options that are not understood.
    //spec| Note that because this specification defines normative behaviors for them,
    //spec| all authenticators MUST understand the "rk", "up", and "uv" options.
    private fun execStep5ProcessOptions() {
        if (options != null) {
            if (BooleanUtil.isTrue(options.uv)) {
                userVerificationPlan = when (ctapAuthenticator.userVerificationSetting) {
                    UserVerificationSetting.READY -> true
                    else -> throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_UNSUPPORTED_OPTION)
                }
            }
            if (BooleanUtil.isTrue(options.up)) {
                userPresencePlan = when (ctapAuthenticator.userPresenceSetting) {
                    UserPresenceSetting.SUPPORTED -> true
                    else -> throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_UNSUPPORTED_OPTION)
                }
            }
        }
    }

    //spec| Step6
    //spec| Optionally, if the extensions parameter is present, process any extensions that this authenticator supports.
    //spec| Authenticator extension outputs generated by the authenticator extension processing are returned in the authenticator data.
    private fun execStep6ProcessExtensions() {
        val inputs = this.authenticationExtensionsAuthenticatorInputs
        assertionObjects = userCredentials.map{ userCredential ->
            val outputsBuilder = AuthenticationExtensionsAuthenticatorOutputs.BuilderForAuthentication()
            if(inputs != null){
                val context = AuthenticationExtensionContext(ctapAuthenticator, authenticatorGetAssertionRequest, userCredential, userVerificationPlan, userPresencePlan)
                ctapAuthenticator.extensionProcessors.filterIsInstance<AuthenticationExtensionProcessor>().forEach{ processor ->
                    if(processor.supportsAuthenticationExtension(inputs)){
                        processor.processAuthenticationExtension(context, outputsBuilder)
                    }
                }
            }
            GetAssertionSession.AssertionObject(userCredential, outputsBuilder.build(), 0)
        }
    }

    //spec| Step7
    //spec| Collect user consentMakeCredential if required. This step MUST happen before the following steps due to privacy reasons
    //spec| (i.e., authenticator cannot disclose existence of a credential until the user interacted with the device):
    private suspend fun execStep7RequestUserConsent() {
        //spec| - If the "uv" option was specified and set to true:
        //spec|   - If device doesn't support user-identifiable gestures, return the CTAP2_ERR_UNSUPPORTED_OPTION error.
        // This is already done in Step6
        //spec|   - Collect a user-identifiable gesture. If gesture validation fails, return the CTAP2_ERR_OPERATION_DENIED error.
        //spec| - If the "up" option was specified and set to true, collect the user’s consentMakeCredential.
        //spec|   - If no consentMakeCredential is obtained and a timeout occurs, return the CTAP2_ERR_OPERATION_DENIED error.
        val options = GetAssertionConsentOptions(rpId, userPresencePlan, userVerificationPlan)
        val permission = ctapAuthenticator.userConsentHandler.consentGetAssertion(options)
        if (permission) {
            if (userVerificationPlan) {
                userVerificationResult = true
            }
            if (userPresencePlan) {
                userPresenceResult = true
            }
        } else {
            throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_OPERATION_DENIED)
        }

    }

    //spec| Step8
    //spec| If no userCredentials were located in step 1, return CTAP2_ERR_NO_CREDENTIALS.
    private fun execStep8CheckUserCredentialCandidatesExistence() {
        if (userCredentials.isEmpty()) {
            throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_NO_CREDENTIALS)
        }
    }

    //spec| Step9
    //spec| If more than one credential was located in step 1 and allowList is present and not empty,
    //spec| select any applicable credential and proceed to step 12.
    //spec| Otherwise, order the userCredentials by the time when they were created in reverse order.
    //spec| The first credential is the most recent credential that was created.
    private fun execStep9SortUserCredentials() {
        userCredentials.sortedBy { userCredential -> userCredential.createdAt.epochSecond }
    }

    //spec| Step10
    //spec| If authenticator does not have a display:
    //spec| - Remember the authenticatorGetAssertion parameters.
    //spec| - Create a credential counter(credentialCounter) and set it 1.
    //spec|   This counter signifies how many userCredentials are sent to the platform by the authenticator.
    //spec| - Start a timer. This is used during authenticatorGetNextAssertion command.
    //spec|   This step is optional if transport is done over NFC.
    //spec| - Update the response to include the first credential’s publicKeyCredentialUserEntity information and numberOfCredentials.
    //spec|   User identifiable information (name, DisplayName, icon) inside publicKeyCredentialUserEntity MUST not be returned
    //spec|   if user verification is not done by the authenticator.
    private fun execStep10PrepareGetAssertionSession() {
        // Let authenticatorData be the byte array specified in §6.1 Authenticator data including processedExtensions,
        // if any, as the extensions and excluding attestedCredentialData.
        var flags: Byte = 0
        // If requireUserVerification is true, the method of obtaining user consentMakeCredential MUST include user verification.
        if (userVerificationResult) {
            flags = flags or AuthenticatorData.BIT_UV
        }
        // If requireUserPresence is true, the method of obtaining user consentMakeCredential MUST include a test of user presence.
        if (userPresenceResult) {
            flags = flags or AuthenticatorData.BIT_UP
        }
        // Let processedExtensions be the result of authenticator extension processing for each supported
        // extension identifier -> authenticator extension input in extensions.

        assertionObjects.forEach{ assertionObject ->
            assertionObject.flags = flags
            if (assertionObject.extensions.keys.isNotEmpty()) {
                assertionObject.flags = assertionObject.flags or AuthenticatorData.BIT_ED
            }
        }
        onGoingGetAssertionSession = GetAssertionSession(assertionObjects, clientDataHash, rpId)
        ctapAuthenticator.onGoingGetAssertionSession = onGoingGetAssertionSession
    }

    //spec| Step11
    //spec| If authenticator has a display:
    //spec| - Display all these userCredentials to the user, using their friendly name along with other stored account information.
    //spec| - Also, display the rpId of the requester (specified in the request) and ask the user to select a credential.
    //spec| - If the user declines to select a credential or takes too long (as determined by the authenticator),
    //spec|   terminate this procedure and return the CTAP2_ERR_OPERATION_DENIED error.
    private suspend fun execStep11SelectUserCredentialIfCredentialSelectorIsAuthenticator() {
        if (ctapAuthenticator.credentialSelectorSetting == CredentialSelectorSetting.AUTHENTICATOR) {
            val selectedUserCredential: UserCredential = ctapAuthenticator.credentialSelectionHandler.select(userCredentials)
            val selectedAssertionObject = assertionObjects.find { it.userCredential == selectedUserCredential }?: throw IllegalStateException("Selected UserCredential is not found in AssertionObject list")
            onGoingGetAssertionSession = onGoingGetAssertionSession.withAssertionObjects(listOf(selectedAssertionObject))
            ctapAuthenticator.onGoingGetAssertionSession = onGoingGetAssertionSession
        }
    }

    //spec| Step12
    //spec| Sign the clientDataHash along with authData with the selected credential, using the structure specified in [WebAuthn].
    private fun execStep12SignClientDataHashAndAuthData(): AuthenticatorGetAssertionResponse {
        val assertionObject = onGoingGetAssertionSession.nextAssertionObject()
        val userCredential = assertionObject.userCredential
        val descriptor = PublicKeyCredentialDescriptor(
            PublicKeyCredentialType.PUBLIC_KEY,
            userCredential.credentialId,
            CtapAuthenticator.TRANSPORTS
        )
        val counter = userCredential.counter
        val authenticatorDataObject = AuthenticatorData(
            onGoingGetAssertionSession.rpIdHash,
            assertionObject.flags,
            counter,
            assertionObject.extensions
        )
        val authData = ctapAuthenticator.authenticatorDataConverter.convert(authenticatorDataObject)

        // Let signature be the assertion signature of the concatenation authenticatorData || hash using
        // the privateKey of selectedCredential as shown in Figure 2, below. A simple, un-delimited concatenation is
        // safe to use here because the authenticator data describes its own length.
        // The hash of the serialized client data (which potentially has a variable length) is always the last element.
        val clientDataHash = onGoingGetAssertionSession.clientDataHash
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
        val numberOfCredentials = onGoingGetAssertionSession.numberOfAssertionObjects

        //spec| On success, the authenticator returns an attestation object in its response as defined in [WebAuthn]:
        val responseData = AuthenticatorGetAssertionResponseData(
            descriptor,
            authData,
            signature,
            user,
            numberOfCredentials
        )

        // update counter
        if (userCredential is ResidentUserCredential) {
            userCredential.counter = counter + 1
            try {
                authenticatorPropertyStore.saveUserCredential(userCredential)
            } catch (e: StoreFullException) {
                throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_KEY_STORE_FULL)
            }
        }
        return AuthenticatorGetAssertionResponse(CtapStatusCode.CTAP2_OK, responseData)
    }

}