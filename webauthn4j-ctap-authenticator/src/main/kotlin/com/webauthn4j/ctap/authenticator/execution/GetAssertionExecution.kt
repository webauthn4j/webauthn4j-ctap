package com.webauthn4j.ctap.authenticator.execution

import tools.jackson.core.type.TypeReference
import com.webauthn4j.ctap.authenticator.CtapAuthenticatorSession
import com.webauthn4j.ctap.authenticator.GetAssertionConsentRequest
import com.webauthn4j.ctap.authenticator.GetAssertionSession
import com.webauthn4j.ctap.authenticator.PinUvAuthProtocol
import com.webauthn4j.ctap.authenticator.SignatureCalculator.calculate
import com.webauthn4j.ctap.authenticator.U2FKeyEnvelope
import com.webauthn4j.ctap.authenticator.data.credential.*
import com.webauthn4j.ctap.authenticator.data.event.GetAssertionEvent
import com.webauthn4j.ctap.authenticator.data.settings.AlwaysUvSetting
import com.webauthn4j.ctap.authenticator.data.settings.ClientPINSetting
import com.webauthn4j.ctap.authenticator.data.settings.CredentialSelectorSetting
import com.webauthn4j.ctap.authenticator.data.settings.UserPresenceSetting
import com.webauthn4j.ctap.authenticator.data.settings.UserVerificationSetting
import com.webauthn4j.ctap.authenticator.extension.AuthenticationExtensionContext
import com.webauthn4j.ctap.authenticator.extension.AuthenticationExtensionProcessor
import com.webauthn4j.ctap.authenticator.store.AuthenticatorPropertyStore
import com.webauthn4j.ctap.authenticator.store.StoreFullException
import com.webauthn4j.ctap.core.data.PinUvAuthTokenPermission
import com.webauthn4j.ctap.core.data.*
import java.util.Arrays
import com.webauthn4j.data.PinProtocolVersion
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

/**
 * GetAssertion command execution
 *
 * @see <a href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-getAssert-authnr-alg">CTAP 2.3 §6.2.2 authenticatorGetAssertion Algorithm</a>
 */
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

    //spec| Step 3. Create a new authenticatorGetAssertion response structure and initialize both its "uv" bit and "up" bit as false.
    private var userVerificationResult = false
    private var userPresenceResult = false

    private var matchedProtocol: PinUvAuthProtocol? = null
    private var uvPerformedViaBuiltIn = false

    private val isProtectedByUserVerification: Boolean
        get() = ctapAuthenticatorSession.isClientPINReady ||
                ctapAuthenticatorSession.userVerification == UserVerificationSetting.READY


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
        execStep1ZeroLengthPinUvAuthParam()
        execStep2ValidatePinUvAuthProtocol()
        // Step 3: response structure initialized via field declarations (userPresenceResult=false, userVerificationResult=false)
        execStep4ProcessOptions()
        execStep5ProcessAlwaysUv()
        execStep6ProcessUserVerification()
        execStep7LocateCredentials()
        execStep8SetUpFromBuiltInUv()
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

    //spec| Step 1. If authenticator supports either pinUvAuthToken or clientPin features and the platform sends a
    //spec| zero length pinUvAuthParam:
    //spec|   Request evidence of user interaction in an authenticator-specific way (e.g., flash the LED light).
    //spec|   If the user declines permission, or the operation times out, then end the operation by returning CTAP2_ERR_OPERATION_DENIED.
    //spec|   If evidence of user interaction is provided in this step then return either
    //spec|   CTAP2_ERR_PIN_NOT_SET if PIN is not set or CTAP2_ERR_PIN_INVALID if PIN has been set.
    //
    // @see https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-getAssert-authnr-alg
    private suspend fun execStep1ZeroLengthPinUvAuthParam() {
        if (pinAuth != null && pinAuth.isEmpty()) {
            //spec| Request evidence of user interaction in an authenticator-specific way (e.g., flash the LED light).
            //spec| If the user declines permission, or the operation times out, then end the operation by returning CTAP2_ERR_OPERATION_DENIED.
            val consent = ctapAuthenticatorSession.withUserPresenceWait {
                ctapAuthenticatorSession.userVerificationHandler.onGetAssertionConsentRequested(
                    GetAssertionConsentRequest(rpId, true, false)
                )
            }
            if (!consent) {
                throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_OPERATION_DENIED)
            }
            //spec| If evidence of user interaction is provided in this step then return either
            //spec| CTAP2_ERR_PIN_NOT_SET if PIN is not set or CTAP2_ERR_PIN_INVALID if PIN has been set.
            if (ctapAuthenticatorSession.isClientPINReady) {
                throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_PIN_INVALID)
            } else {
                throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_PIN_NOT_SET)
            }
        }
    }

    //spec| Step 2. If the pinUvAuthParam parameter is present:
    //spec|   If the pinUvAuthProtocol parameter's value is not supported, return CTAP1_ERR_INVALID_PARAMETER error.
    //spec|   If the pinUvAuthProtocol parameter is absent, return CTAP2_ERR_MISSING_PARAMETER error.
    //
    // @see https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-getAssert-authnr-alg
    private fun execStep2ValidatePinUvAuthProtocol() {
        if (pinAuth != null) {
            //spec| If the pinUvAuthProtocol parameter is absent, return CTAP2_ERR_MISSING_PARAMETER error.
            if (pinProtocol == null) {
                throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_MISSING_PARAMETER)
            }
            //spec| If the pinUvAuthProtocol parameter's value is not supported, return CTAP1_ERR_INVALID_PARAMETER error.
            if (ctapAuthenticatorSession.pinProtocols.none { it == pinProtocol }) {
                throw CtapCommandExecutionException(CtapStatusCode.CTAP1_ERR_INVALID_PARAMETER)
            }
        }
    }

    //spec| Step 4. If the options parameter is present, process all option keys and values present in the parameter.
    //spec| Treat any option keys that are not understood as absent.
    //spec|   If the "uv" option is absent, let the "uv" option be treated as being present with the value false. (This is the default)
    //spec|   If the pinUvAuthParam is present, let the "uv" option be treated as being present with the value false.
    //spec|   If the "uv" option is present and true then:
    //spec|     If the authenticator does not support a built-in user verification method end the operation by returning CTAP2_ERR_INVALID_OPTION.
    //spec|     If the built-in user verification method has not yet been enabled, end the operation by returning CTAP2_ERR_INVALID_OPTION.
    //spec|   If the "rk" option is present then:
    //spec|     Return CTAP2_ERR_UNSUPPORTED_OPTION.
    //spec|   If the "up" option is not present then:
    //spec|     Let the "up" option be treated as being present with the value true. (This is the default)
    //
    // @see https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-getAssert-authnr-alg
    private fun execStep4ProcessOptions() {
        if (options != null) {
            //spec| If the pinUvAuthParam is present, let the "uv" option be treated as being present with the value false.
            userVerificationPlan = if (pinAuth != null) {
                false
            } else {
                when {
                    //spec| If the "uv" option is present and true then:
                    //spec|   If the authenticator does not support a built-in user verification method end the operation by returning CTAP2_ERR_INVALID_OPTION.
                    //spec|   If the built-in user verification method has not yet been enabled, end the operation by returning CTAP2_ERR_INVALID_OPTION.
                    BooleanUtil.isTrue(options.uv) -> {
                        when (ctapAuthenticatorSession.userVerification) {
                            UserVerificationSetting.READY -> true
                            else -> throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_INVALID_OPTION)
                        }
                    }
                    //spec| If the "uv" option is absent, let the "uv" option be treated as being present with the value false. (This is the default)
                    else -> false
                }
            }
            userPresencePlan = if (options.up != false) {
                when (ctapAuthenticatorSession.userPresence) {
                    UserPresenceSetting.SUPPORTED -> true
                    else -> throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_INVALID_OPTION)
                }
            } else {
                false
            }
        } else {
            //spec| If the "up" option is not present then:
            //spec|   Let the "up" option be treated as being present with the value true. (This is the default)
            userPresencePlan = when (ctapAuthenticatorSession.userPresence) {
                UserPresenceSetting.SUPPORTED -> true
                else -> throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_INVALID_OPTION)
            }
        }
    }

    //spec| Step 5. If the alwaysUv option ID is present and true and the "up" option is present and true then:
    //spec|   If the authenticator is not protected by some form of user verification:
    //spec|     If the clientPin option ID is present and noMcGaPermissionsWithClientPin option ID is absent or false
    //spec|     (clientPin is supported for the ga permission):
    //spec|       End the operation by returning CTAP2_ERR_PUAT_REQUIRED.
    //spec|     Else (clientPin is not supported):
    //spec|       End the operation by returning CTAP2_ERR_OPERATION_DENIED.
    //
    // @see https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-getAssert-authnr-alg
    private fun execStep5ProcessAlwaysUv() {
        if (ctapAuthenticatorSession.alwaysUv != AlwaysUvSetting.ENABLED) return
        if (!userPresencePlan) return

        //spec| If the authenticator is not protected by some form of user verification:
        if (!isProtectedByUserVerification) {
            //spec| If the clientPin option ID is present and noMcGaPermissionsWithClientPin option ID is absent or false:
            //spec|   End the operation by returning CTAP2_ERR_PUAT_REQUIRED.
            //spec| Else (clientPin is not supported):
            //spec|   End the operation by returning CTAP2_ERR_OPERATION_DENIED.
            if (ctapAuthenticatorSession.clientPIN == ClientPINSetting.ENABLED) {
                throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_PUAT_REQUIRED)
            } else {
                throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_OPERATION_DENIED)
            }
        }

        //spec| If the pinUvAuthParam is present then go to Step 6.
        //spec| If the "uv" option is true then go to Step 6.
        //spec| If the "uv" option is false and the authenticator supports a built-in user verification method,
        //spec| and the user verification method is enabled then:
        //spec|   Let the "uv" option be treated as being present with the value true.
        if (pinAuth == null && !userVerificationPlan) {
            if (ctapAuthenticatorSession.userVerification == UserVerificationSetting.READY) {
                userVerificationPlan = true
            } else if (ctapAuthenticatorSession.clientPIN == ClientPINSetting.ENABLED) {
                throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_PUAT_REQUIRED)
            } else {
                throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_OPERATION_DENIED)
            }
        }
    }

    //spec| Step 6. If the authenticator is protected by some form of user verification, then:
    //spec|   6.1 If pinUvAuthParam parameter is present (implying the "uv" option is treated as false, see Step 4):
    //spec|     Call verify(pinUvAuthToken, clientDataHash, pinUvAuthParam).
    //spec|     If the verification returns error, return CTAP2_ERR_PIN_AUTH_INVALID error.
    //spec|     If the verification returns success, set the "uv" bit to true in the response.
    //spec|     Let userVerifiedFlagValue be the result of calling getUserVerifiedFlagValue().
    //spec|     If userVerifiedFlagValue is false then end the operation by returning CTAP2_ERR_PIN_AUTH_INVALID.
    //spec|     Verify that the pinUvAuthToken has the ga permission, if not, return CTAP2_ERR_PIN_AUTH_INVALID.
    //spec|     If the pinUvAuthToken has a permissions RP ID associated:
    //spec|       If the permissions RP ID does not match the rpId in this request, return CTAP2_ERR_PIN_AUTH_INVALID.
    //spec|     If the pinUvAuthToken does not have a permissions RP ID associated:
    //spec|       Associate the request's rpId parameter value with the pinUvAuthToken as its permissions RP ID.
    //spec|     Go to Step 7.
    //spec|   6.2 If the "uv" option is present and set to true (implying the pinUvAuthParam parameter is not present,
    //spec|   and that the authenticator supports an enabled built-in user verification method, see Step 4):
    //spec|     Let internalRetry be true.
    //spec|     Let uvState be the result of calling performBuiltInUv(internalRetry)
    //spec|     If uvState is error:
    //spec|       If the error reason is a user action timeout, then return CTAP2_ERR_USER_ACTION_TIMEOUT.
    //spec|       If the uvRetries counter is 0, return CTAP2_ERR_PIN_BLOCKED.
    //spec|       Otherwise, end the operation by returning CTAP2_ERR_OPERATION_DENIED.
    //spec|     If uvState is success:
    //spec|       Set the "uv" bit to true in the response.
    //
    // @see https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-getAssert-authnr-alg
    private fun execStep6ProcessUserVerification() {
        if (!isProtectedByUserVerification) return

        //spec| 6.1 If pinUvAuthParam parameter is present (implying the "uv" option is treated as false, see Step 4):
        if (pinAuth != null && pinProtocol != null) {
            //spec| Call verify(pinUvAuthToken, clientDataHash, pinUvAuthParam).
            //spec| If the verification returns error, return CTAP2_ERR_PIN_AUTH_INVALID error.
            val protocol = ctapAuthenticatorSession.pinUvAuthManager.pinUvAuthProtocols.firstOrNull { protocol ->
                protocol.verify(protocol.pinUvAuthToken, clientDataHash, pinAuth)
            } ?: throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_PIN_AUTH_INVALID)

            //spec| If the verification returns success, set the "uv" bit to true in the response.
            userVerificationResult = true

            //spec| Let userVerifiedFlagValue be the result of calling getUserVerifiedFlagValue().
            //spec| If userVerifiedFlagValue is false then end the operation by returning CTAP2_ERR_PIN_AUTH_INVALID.
            if (!protocol.tokenState.getUserVerifiedFlagValue()) {
                throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_PIN_AUTH_INVALID)
            }

            //spec| Verify that the pinUvAuthToken has the ga permission, if not, return CTAP2_ERR_PIN_AUTH_INVALID.
            if (!protocol.tokenState.hasPermission(PinUvAuthTokenPermission.GA)) {
                throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_PIN_AUTH_INVALID)
            }

            //spec| If the pinUvAuthToken has a permissions RP ID associated:
            //spec|   If the permissions RP ID does not match the rpId in this request, return CTAP2_ERR_PIN_AUTH_INVALID.
            val tokenRpId = protocol.tokenState.permissionsRpId
            if (tokenRpId != null && tokenRpId != rpId) {
                throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_PIN_AUTH_INVALID)
            }

            //spec| If the pinUvAuthToken does not have a permissions RP ID associated:
            //spec|   Associate the request's rpId parameter value with the pinUvAuthToken as its permissions RP ID.
            if (protocol.tokenState.permissionsRpId == null) {
                protocol.tokenState.permissionsRpId = rpId
            }

            protocol.tokenState.recordPlatformUsage()
            matchedProtocol = protocol
            //spec| Go to Step 7.
            return
        }

        //spec| 6.2 If the "uv" option is present and set to true (implying the pinUvAuthParam parameter is not present,
        //spec| and that the authenticator supports an enabled built-in user verification method, see Step 4):
        // Built-in UV is handled via the consent flow in Step 9.
        // userVerificationPlan remains true and will be processed during consent.
    }

    //spec| Step 7. Locate all credentials that are eligible for retrieval under the specified criteria:
    //spec|   If the allowList parameter is present and is non-empty, locate all
    //spec|   denoted credentials created by this authenticator and bound to the specified rpId.
    //spec|   If an allowList is not present, locate all discoverable credentials that are
    //spec|   created by this authenticator and bound to the specified rpId.
    //spec|   Create an applicable credentials list populated with the located credentials.
    //spec|   If the applicable credentials list is empty, return CTAP2_ERR_NO_CREDENTIALS.
    //
    // @see https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-getAssert-authnr-alg
    private fun execStep7LocateCredentials() {
        val rpId = rpId

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

    //spec| Step 8. If evidence of user interaction was provided as part of Step 6.2 (i.e., by invoking performBuiltInUv()):
    //spec|   Set the "up" bit to true in the response.
    //spec|   Go to Step 10
    //
    // @see https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-getAssert-authnr-alg
    private fun execStep8SetUpFromBuiltInUv(): Boolean {
        if (uvPerformedViaBuiltIn) {
            userPresenceResult = true
            return true
        }
        return false
    }

    //spec| Step 9. If the "up" option is set to true or not present:
    //spec|   If the pinUvAuthParam parameter is present then:
    //spec|     Let userPresentFlagValue be the result of calling getUserPresentFlagValue().
    //spec|     If userPresentFlagValue is false:
    //spec|       Request evidence of user interaction in an authenticator-specific way (e.g., flash the LED light).
    //spec|       If the authenticator has a display, show the rpId parameter value to the user,
    //spec|       and request permission to create an assertion.
    //spec|       If the user declines permission, or the operation times out, then end the operation by returning CTAP2_ERR_OPERATION_DENIED.
    //spec|   Else (implying the pinUvAuthParam parameter is not present):
    //spec|     If the "up" bit is false in the response:
    //spec|       Request evidence of user interaction in an authenticator-specific way (e.g., flash the LED light).
    //spec|       If the authenticator has a display, show the rpId parameter value to the user,
    //spec|       and request permission to create an assertion.
    //spec|       If the user declines permission, or the operation times out, then end the operation by returning CTAP2_ERR_OPERATION_DENIED.
    //spec|   Set the "up" bit to true in the response.
    //spec|   Call clearUserPresentFlag(), clearUserVerifiedFlag(), and clearPinUvAuthTokenPermissionsExceptLbw().
    //
    // @see https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-getAssert-authnr-alg
    private suspend fun execStep9RequestUserConsent() {
        if (userPresencePlan) {
            var needsInteraction = false

            //spec| If the pinUvAuthParam parameter is present then:
            if (pinAuth != null) {
                //spec| Let userPresentFlagValue be the result of calling getUserPresentFlagValue().
                //spec| If userPresentFlagValue is false:
                val protocol = matchedProtocol
                if (protocol != null && !protocol.tokenState.getUserPresentFlagValue()) {
                    needsInteraction = true
                } else if (protocol == null) {
                    needsInteraction = true
                }
            } else {
                //spec| Else (implying the pinUvAuthParam parameter is not present):
                //spec|   If the "up" bit is false in the response:
                if (!userPresenceResult) {
                    needsInteraction = true
                }
            }

            if (needsInteraction) {
                //spec| Request evidence of user interaction in an authenticator-specific way (e.g., flash the LED light).
                //spec| If the user declines permission, or the operation times out, then end the operation by returning CTAP2_ERR_OPERATION_DENIED.
                val consentRequest = GetAssertionConsentRequest(rpId, userPresencePlan, userVerificationPlan)
                val consent = ctapAuthenticatorSession.withUserPresenceWait {
                    ctapAuthenticatorSession.userVerificationHandler.onGetAssertionConsentRequested(consentRequest)
                }
                if (!consent) {
                    throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_OPERATION_DENIED)
                }
                if (userVerificationPlan) {
                    userVerificationResult = true
                }
            }

            //spec| Set the "up" bit to true in the response.
            userPresenceResult = true

            //spec| Call clearUserPresentFlag(), clearUserVerifiedFlag(), and clearPinUvAuthTokenPermissionsExceptLbw().
            ctapAuthenticatorSession.pinUvAuthManager.pinUvAuthProtocols.forEach { protocol ->
                protocol.tokenState.clearUserPresentFlag()
                protocol.tokenState.clearUserVerifiedFlag()
                protocol.tokenState.clearPinUvAuthTokenPermissionsExceptLbw()
            }
        }
    }

    //spec| Step 10. If the extensions parameter is present:
    //spec|   Process any extensions that this authenticator supports, ignoring any that it does not support.
    //spec|   Authenticator extension outputs generated by the authenticator extension processing
    //spec|   are returned in the authenticator data.
    //spec|   The set of keys in the authenticator extension outputs map MUST be equal to, or a subset of, the keys of the authenticator extension inputs map.
    //
    // @see https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-getAssert-authnr-alg
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

    //spec| Step 11. If the allowList parameter is present:
    //spec|   Select any credential from the applicable credentials list.
    //spec| Step 12. If allowList is not present:
    //spec|   Order the credentials in the applicable credentials list by the time when they were created in reverse order.
    //
    // @see https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-getAssert-authnr-alg
    private suspend fun execStep11And12SelectCredential() {
        // Sort credentials by creation time in reverse order (most recent first)
        assertionObjects = assertionObjects.sortedByDescending { it.credential.createdAt.epochSecond }

        // Mask user identifiable information if user verification was not performed
        if (!userVerificationResult && pinAuth == null) {
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

    //spec| Step 13. Sign the clientDataHash along with authData with the selected credential, using the structure specified in [WebAuthn].
    //
    // @see https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-getAssert-authnr-alg
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
