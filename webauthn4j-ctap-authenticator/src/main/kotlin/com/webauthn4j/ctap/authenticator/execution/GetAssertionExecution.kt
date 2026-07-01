package com.webauthn4j.ctap.authenticator.execution

import tools.jackson.core.type.TypeReference
import com.webauthn4j.ctap.authenticator.CtapAuthenticatorSession
import com.webauthn4j.ctap.authenticator.GetAssertionConsentRequest
import com.webauthn4j.ctap.authenticator.GetAssertionSession
import com.webauthn4j.ctap.authenticator.SignatureCalculator.calculate
import com.webauthn4j.ctap.authenticator.U2FKeyEnvelope
import com.webauthn4j.ctap.authenticator.data.credential.*
import com.webauthn4j.ctap.authenticator.data.event.GetAssertionEvent
import com.webauthn4j.ctap.authenticator.data.settings.CredentialSelectorSetting
import com.webauthn4j.ctap.authenticator.data.settings.UserPresenceSetting
import com.webauthn4j.ctap.authenticator.data.settings.UserVerificationSetting
import com.webauthn4j.ctap.authenticator.extension.AuthenticationExtensionContext
import com.webauthn4j.ctap.authenticator.extension.AuthenticationExtensionProcessor
import com.webauthn4j.ctap.authenticator.store.AuthenticatorPropertyStore
import com.webauthn4j.ctap.authenticator.store.StoreFullException
import com.webauthn4j.ctap.core.data.*
import com.webauthn4j.ctap.core.util.internal.BooleanUtil
import com.webauthn4j.ctap.core.util.internal.CipherUtil
import com.webauthn4j.ctap.core.util.internal.HexUtil
import com.webauthn4j.ctap.core.validator.AuthenticatorGetAssertionRequestValidator
import com.webauthn4j.data.PublicKeyCredentialDescriptor
import com.webauthn4j.data.PublicKeyCredentialType
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
import kotlin.experimental.or

// @see <a href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-getAssert-authnr-alg">6.2.2. authenticatorGetAssertion Algorithm</a>
@Suppress("ConvertSecondaryConstructorToPrimary")
internal class GetAssertionExecution :
    CtapCommandExecutionBase<AuthenticatorGetAssertionRequest, AuthenticatorGetAssertionResponse> {

    override val commandName: String = "GetAssertion"

    @Suppress("JoinDeclarationAndAssignment")
    private val ctapAuthenticatorSession: CtapAuthenticatorSession

    private val logger: Logger = LoggerFactory.getLogger(GetAssertionExecution::class.java)
    private val getAssertionRequestValidator = AuthenticatorGetAssertionRequestValidator()
    private val authenticatorPropertyStore: AuthenticatorPropertyStore

    //Command properties
    @Suppress("JoinDeclarationAndAssignment")
    private val authenticatorGetAssertionRequest: AuthenticatorGetAssertionRequest
    private val rpId: String
    private val rpIdHash: ByteArray
    private val clientDataHash: ByteArray
    private val allowList: List<PublicKeyCredentialDescriptor>?
    private val authenticationExtensionsAuthenticatorInputs: AuthenticationExtensionsAuthenticatorInputs<AuthenticationExtensionAuthenticatorInput>?
    private val options: AuthenticatorGetAssertionRequest.Options?
    private val pinAuth: ByteArray?
    private val pinProtocol: PinProtocolVersion?

    // initialized in Step7
    private lateinit var credentials: List<Credential>

    // initialized in Step10
    private lateinit var assertionObjects: List<GetAssertionSession.AssertionObject>

    // initialized in Step11And12
    private lateinit var onGoingGetAssertionSession: GetAssertionSession

    private var userVerificationPlan = false
    private var userPresencePlan = false
    private var userVerificationResult = false
    private var userPresenceResult = false


    constructor(
        ctapAuthenticatorSession: CtapAuthenticatorSession,
        authenticatorGetAssertionRequest: AuthenticatorGetAssertionRequest
    ) : super(ctapAuthenticatorSession, authenticatorGetAssertionRequest) {
        this.authenticatorGetAssertionRequest = authenticatorGetAssertionRequest
        this.ctapAuthenticatorSession = ctapAuthenticatorSession
        this.authenticatorPropertyStore = ctapAuthenticatorSession.authenticatorPropertyStore

        // command properties initialization and validation
        this.rpId = authenticatorGetAssertionRequest.rpId

        this.rpIdHash = MessageDigestUtil.createSHA256().digest(rpId.toByteArray())
        this.clientDataHash = authenticatorGetAssertionRequest.clientDataHash
        this.allowList = authenticatorGetAssertionRequest.allowList
        this.authenticationExtensionsAuthenticatorInputs =
            authenticatorGetAssertionRequest.extensions
        this.options = authenticatorGetAssertionRequest.options
        this.pinAuth = authenticatorGetAssertionRequest.pinAuth
        this.pinProtocol = authenticatorGetAssertionRequest.pinProtocol
    }

    override suspend fun validate() {
        getAssertionRequestValidator.validate(authenticatorGetAssertionRequest)
    }

    override suspend fun doExecute(): AuthenticatorGetAssertionResponse {
        // execStep1ZeroLengthPinUvAuthParam()     // TODO: CTAP 2.1
        // execStep2ValidatePinUvAuthProtocol()     // TODO: CTAP 2.1
        // execStep3InitializeResponseStructure()   // TODO: CTAP 2.1
        execStep4ProcessOptions()
        // execStep5ProcessAlwaysUv()               // TODO: CTAP 2.1
        execStep6ProcessUserVerification()
        execStep7LocateCredentials()
        // execStep8SetUpFromBuiltInUv()            // TODO: CTAP 2.1
        execStep9RequestUserConsent()
        execStep10ProcessExtensions()
        execStep11And12SelectCredential()
        val response = execStep13Sign()
        val userCredentials = onGoingGetAssertionSession.assertionObjects.map {
            when (val credential = it.credential) {
                is UserCredential -> {
                    GetAssertionEvent.UserCredential(
                        credential.credentialId,
                        credential.username,
                        credential.displayName
                    )
                }
                else -> {
                    GetAssertionEvent.UserCredential(
                        credential.credentialId
                    )
                }
            }

        }
        val rpName =
            onGoingGetAssertionSession.assertionObjects.map { (it.credential as? UserCredential)?.rpName }
                .firstOrNull() ?: "N/A (U2F service)"
        val event = GetAssertionEvent(Instant.now(), rpId, rpName, userCredentials, mapOf())
        ctapAuthenticatorSession.publishEvent(event)
        return response
    }


    override fun createErrorResponse(statusCode: CtapStatusCode): AuthenticatorGetAssertionResponse {
        return AuthenticatorGetAssertionResponse(statusCode)
    }

    //spec| Step 4
    //spec| If the options parameter is present, process all option keys and values present in the parameter.
    //spec| Treat any option keys that are not understood as absent.
    //spec| @see <a href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-getAssert-authnr-alg">6.2.2. authenticatorGetAssertion Algorithm</a>
    private fun execStep4ProcessOptions() {
        if (options != null) {
            if (BooleanUtil.isTrue(options.uv)) {
                userVerificationPlan = when (ctapAuthenticatorSession.userVerification) {
                    UserVerificationSetting.READY -> true
                    else -> throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_UNSUPPORTED_OPTION)
                }
            }
            if (options.up != false) {
                userPresencePlan = when (ctapAuthenticatorSession.userPresence) {
                    UserPresenceSetting.SUPPORTED -> true
                    else -> throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_UNSUPPORTED_OPTION)
                }
            }
        }
    }

    //spec| Step 6
    //spec| If the authenticator is protected by some form of user verification, then:
    //spec| @see <a href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-getAssert-authnr-alg">6.2.2. authenticatorGetAssertion Algorithm</a>
    private fun execStep6ProcessUserVerification() {
        // If pinUvAuthParam parameter is present and pinProtocol is supported,
        // verify it and set the "uv" bit to true in the response.
        if (pinAuth != null && pinProtocol == PinProtocolVersion.VERSION_1) {
            val clientDataHash = clientDataHash
            val pinAuth = pinAuth
            ctapAuthenticatorSession.clientPINService.validatePINAuth(pinAuth, clientDataHash)
            userVerificationResult = true
            return
        }
        // If pinUvAuthParam parameter is present and the pinProtocol is not supported,
        // return CTAP2_ERR_PIN_AUTH_INVALID.
        if (pinAuth != null && pinProtocol != PinProtocolVersion.VERSION_1) {
            throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_PIN_AUTH_INVALID)
        }
        // If pinUvAuthParam parameter is not present and clientPin has been set on the authenticator,
        // set the "uv" bit to false in the response.
        if (pinAuth == null && ctapAuthenticatorSession.clientPINService.isClientPINReady) {
            userVerificationResult = false
        }
    }

    //spec| Step 7
    //spec| Locate all credentials that are eligible for retrieval under the specified criteria:
    //spec| @see <a href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-getAssert-authnr-alg">6.2.2. authenticatorGetAssertion Algorithm</a>
    private fun execStep7LocateCredentials() {
        val rpId = rpId

        //spec| If the allowList parameter is present and is non-empty, locate all
        //spec| denoted credentials created by this authenticator and bound to the specified rpId.
        //spec| If an allowList is not present, locate all discoverable credentials that are
        //spec| created by this authenticator and bound to the specified rpId.
        credentials = if (allowList != null && allowList.isNotEmpty()) {
            val storedCredentials = authenticatorPropertyStore.loadUserCredentials(rpId)
                .filter {
                    allowList.any { allowed: PublicKeyCredentialDescriptor ->
                        it.credentialId.contentEquals(
                            allowed.id
                        )
                    }
                }.filter { it.rpIdHash.contentEquals(rpIdHash) }
            val derivedCredentials = allowList.mapNotNull(this::deriveCredential)
            val result: MutableList<Credential> = ArrayList()
            result.addAll(storedCredentials)
            result.addAll(derivedCredentials)
            result
        } else {
            ArrayList<Credential>(
                authenticatorPropertyStore.loadUserCredentials(
                    rpId
                )
            )
        }

        //spec| If the applicable credentials list is empty, return CTAP2_ERR_NO_CREDENTIALS.
        if (credentials.isEmpty()) {
            throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_NO_CREDENTIALS)
        }
    }

    private fun deriveCredential(descriptor: PublicKeyCredentialDescriptor): Credential? {
        val credentialSourceEncryptionKey = authenticatorPropertyStore.loadEncryptionKey()
        val credentialSourceEncryptionIV = authenticatorPropertyStore.loadEncryptionIV()
        val decrypted: ByteArray
        try {
            decrypted = CipherUtil.decryptWithAESCBCPKCS5Padding(
                descriptor.id,
                credentialSourceEncryptionKey,
                credentialSourceEncryptionIV
            )!!
        } catch (e: RuntimeException) {
            logger.debug(
                "Skipped credentialId: %s as it doesn't contain valid NonResidentUserCredentialSource.".format(
                    HexUtil.encodeToString(descriptor.id)
                )
            )
            return null
        }
        try {
            val nonResidentUserCredentialEnvelope =
                ctapAuthenticatorSession.objectConverter.cborMapper.readValue(
                    decrypted,
                    object : TypeReference<NonResidentUserCredentialSource>() {})!!
            return NonResidentUserCredential(
                descriptor.id,
                nonResidentUserCredentialEnvelope.userCredentialKey,
                nonResidentUserCredentialEnvelope.userHandle,
                nonResidentUserCredentialEnvelope.username,
                nonResidentUserCredentialEnvelope.displayName,
                nonResidentUserCredentialEnvelope.icon,
                nonResidentUserCredentialEnvelope.rpId,
                nonResidentUserCredentialEnvelope.rpName,
                nonResidentUserCredentialEnvelope.rpIcon,
                nonResidentUserCredentialEnvelope.createdAt,
                nonResidentUserCredentialEnvelope.otherUI,
                nonResidentUserCredentialEnvelope.details
            )
        } catch (e: RuntimeException) {
            logger.trace("Failed to load NonResidentUserCredentialSource from credentialId", e)
        }
        try {
            val u2fKeyEnvelope =
                ctapAuthenticatorSession.objectConverter.cborMapper.readValue(
                    decrypted,
                    object : TypeReference<U2FKeyEnvelope>() {})!!

            val key = NonResidentCredentialKey(
                SignatureAlgorithm.ES256,
                u2fKeyEnvelope.keyPair.publicKey!!,
                u2fKeyEnvelope.keyPair.privateKey!!
            )
            return U2FCredential(
                descriptor.id,
                u2fKeyEnvelope.applicationParameter,
                key,
                0,
                u2fKeyEnvelope.createdAt,
                emptyMap()
            )
        } catch (e: RuntimeException) {
            logger.trace("Failed to load U2FKeyEnvelope from credentialId", e)
        }
        return null
    }

    //spec| Step 9
    //spec| If the "up" option is set to true or not present:
    //spec| @see <a href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-getAssert-authnr-alg">6.2.2. authenticatorGetAssertion Algorithm</a>
    private suspend fun execStep9RequestUserConsent() {
        val options = GetAssertionConsentRequest(rpId, userPresencePlan, userVerificationPlan)
        val consent = ctapAuthenticatorSession.withUserPresenceWait {
            ctapAuthenticatorSession.userVerificationHandler.onGetAssertionConsentRequested(options)
        }
        if (consent) {
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

    //spec| Step 10
    //spec| If the extensions parameter is present:
    //spec| @see <a href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-getAssert-authnr-alg">6.2.2. authenticatorGetAssertion Algorithm</a>
    private fun execStep10ProcessExtensions() {
        val inputs = this.authenticationExtensionsAuthenticatorInputs
        assertionObjects = credentials.map { credential ->
            val outputsBuilder =
                AuthenticationExtensionsAuthenticatorOutputs.BuilderForAuthentication()
            if (inputs != null) {
                val context = AuthenticationExtensionContext(
                    ctapAuthenticatorSession,
                    authenticatorGetAssertionRequest,
                    credential,
                    userVerificationPlan,
                    userPresencePlan
                )
                ctapAuthenticatorSession.extensionProcessors.filterIsInstance<AuthenticationExtensionProcessor>()
                    .forEach { processor ->
                        if (processor.supportsAuthenticationExtension(inputs)) {
                            processor.processAuthenticationExtension(context, outputsBuilder)
                        }
                    }
            }
            GetAssertionSession.AssertionObject(credential, false, outputsBuilder.build(), 0)
        }
    }

    //spec| Step 11
    //spec| If the allowList parameter is present:
    //spec| Step 12
    //spec| If allowList is not present:
    //spec| @see <a href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-getAssert-authnr-alg">6.2.2. authenticatorGetAssertion Algorithm</a>
    private suspend fun execStep11And12SelectCredential() {
        // Sort credentials by creation time in reverse order (most recent first)
        assertionObjects = assertionObjects.sortedByDescending { it.credential.createdAt.epochSecond }

        // Mask user identifiable information if user verification was not performed
        if (!(userVerificationPlan || authenticatorGetAssertionRequest.pinAuth != null)) {
            assertionObjects.map {
                it.maskUserIdentifiableInfo = true
            }
        }

        // Build authenticator data flags
        var flags: Byte = 0
        if (userVerificationResult) {
            flags = flags or AuthenticatorData.BIT_UV
        }
        if (userPresenceResult) {
            flags = flags or AuthenticatorData.BIT_UP
        }

        assertionObjects.forEach { assertionObject ->
            assertionObject.flags = flags
            if (assertionObject.extensions.keys.isNotEmpty()) {
                assertionObject.flags = assertionObject.flags or AuthenticatorData.BIT_ED
            }
        }
        onGoingGetAssertionSession = GetAssertionSession(assertionObjects, clientDataHash)
        ctapAuthenticatorSession.onGoingGetAssertionSession = onGoingGetAssertionSession

        // If authenticator has a display, let user select a credential
        if (ctapAuthenticatorSession.credentialSelector == CredentialSelectorSetting.AUTHENTICATOR) {
            val selectedCredential: Credential =
                ctapAuthenticatorSession.credentialSelectionHandler.onSelect(credentials)
            val selectedAssertionObject =
                assertionObjects.find { it.credential.credentialId.contentEquals(selectedCredential.credentialId) }
                    ?: throw IllegalStateException("Selected Credential is not found in AssertionObject list")
            onGoingGetAssertionSession =
                onGoingGetAssertionSession.withAssertionObjects(listOf(selectedAssertionObject))
            ctapAuthenticatorSession.onGoingGetAssertionSession = onGoingGetAssertionSession
        }
    }

    //spec| Step 13
    //spec| Sign the clientDataHash along with authData with the selected credential, using the structure specified in [WebAuthn].
    //spec| @see <a href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-getAssert-authnr-alg">6.2.2. authenticatorGetAssertion Algorithm</a>
    private fun execStep13Sign(): AuthenticatorGetAssertionResponse {
        val assertionObject = onGoingGetAssertionSession.nextAssertionObject()
        val credential = assertionObject.credential
        val descriptor = PublicKeyCredentialDescriptor(
            PublicKeyCredentialType.PUBLIC_KEY,
            credential.credentialId,
            ctapAuthenticatorSession.transports
        )
        val counter = credential.counter
        val authenticatorDataObject = AuthenticatorData(
            assertionObject.credential.rpIdHash,
            assertionObject.flags,
            counter,
            assertionObject.extensions
        )
        val authData = ctapAuthenticatorSession.authenticatorDataConverter.convert(authenticatorDataObject)

        // Let signature be the assertion signature of the concatenation authenticatorData || hash using
        // the privateKey of selectedCredential as shown in Figure 2, below. A simple, un-delimited concatenation is
        // safe to use here because the authenticator data describes its own length.
        // The hash of the serialized client data (which potentially has a variable length) is always the last element.
        val clientDataHash = onGoingGetAssertionSession.clientDataHash
        val signedData = ByteBuffer.allocate(authData.size + clientDataHash.size).put(authData)
            .put(clientDataHash).array()
        val signature = calculate(
            credential.credentialKey.alg!!,
            credential.credentialKey.keyPair!!.private,
            signedData
        )
        val user = when (credential) {
            is UserCredential -> when (assertionObject.maskUserIdentifiableInfo) {
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
        if (credential is ResidentUserCredential) {
            credential.counter = counter + 1
            try {
                authenticatorPropertyStore.saveUserCredential(credential)
            } catch (e: StoreFullException) {
                throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_KEY_STORE_FULL)
            }
        }
        return AuthenticatorGetAssertionResponse(CtapStatusCode.CTAP2_OK, responseData)
    }

}
