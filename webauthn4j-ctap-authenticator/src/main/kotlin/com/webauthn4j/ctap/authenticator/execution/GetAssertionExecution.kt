package com.webauthn4j.ctap.authenticator.execution

import tools.jackson.core.type.TypeReference
import com.webauthn4j.ctap.authenticator.CtapAuthenticatorSession
import com.webauthn4j.ctap.authenticator.CredentialSelectionCanceledException
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
import com.webauthn4j.ctap.authenticator.extension.GetAssertionCredentialFilter
import com.webauthn4j.ctap.authenticator.extension.GetAssertionCredentialFilterContext
import com.webauthn4j.ctap.authenticator.extension.AuthenticationExtensionContext
import com.webauthn4j.ctap.authenticator.extension.AuthenticationExtensionProcessor
import com.webauthn4j.ctap.authenticator.store.AuthenticatorPropertyStore
import com.webauthn4j.ctap.authenticator.store.StoreFullException
import com.webauthn4j.ctap.core.data.PinUvAuthTokenPermission
import com.webauthn4j.ctap.core.data.*
import com.webauthn4j.data.PinProtocolVersion
import com.webauthn4j.ctap.core.util.internal.CipherUtil
import com.webauthn4j.ctap.core.util.internal.HexUtil
import com.webauthn4j.ctap.core.validator.AuthenticatorGetAssertionRequestValidator
import com.webauthn4j.data.PublicKeyCredentialDescriptor
import com.webauthn4j.data.PublicKeyCredentialType
import com.webauthn4j.data.PublicKeyCredentialUserEntity
import com.webauthn4j.data.attestation.authenticator.EC2COSEKey
import java.security.KeyPair
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier
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

    private val logger: Logger = LoggerFactory.getLogger(GetAssertionExecution::class.java)
    private val getAssertionRequestValidator = AuthenticatorGetAssertionRequestValidator()

    @Suppress("JoinDeclarationAndAssignment")
    private val ctapAuthenticatorSession: CtapAuthenticatorSession
    private val authenticatorGetAssertionRequest: AuthenticatorGetAssertionRequest

    private val authenticatorPropertyStore: AuthenticatorPropertyStore

    // command properties
    private val rpId: String
    private val rpIdHash: ByteArray
    private val clientDataHash: ByteArray
    private val allowList: List<PublicKeyCredentialDescriptor>?
    private val authenticationExtensionsAuthenticatorInputs: AuthenticationExtensionsAuthenticatorInputs<AuthenticationExtensionAuthenticatorInput>?
    private val options: AuthenticatorGetAssertionRequest.Options?
    private val pinUvAuthParam: ByteArray?
    private val pinUvAuthProtocol: PinProtocolVersion?

    private var shouldPerformUv = false
    private var shouldPerformUp = false

    //spec| Step 3. Create a new authenticatorGetAssertion response structure and initialize both its "uv" bit and "up" bit as false.
    private var uvResult = false
    private var upResult = false

    private lateinit var protocol: PinUvAuthProtocol
    // Step 6.2: result of performBuiltInUv(). When true (success), Step 8 sets UP from the UV
    // evidence and Step 9 (explicit UP test) is skipped.
    private var uvState = false

    // Step 11.2: set to true when allowList is present (numberOfCredentials is deleted from response).
    private var suppressNumberOfCredentials = false
    // Step 12.2.3.4: set to true when user selects a credential via authenticator display.
    private var userSelected = false

    // initialized in Step 7
    private lateinit var credentials: List<Credential>

    // initialized in Step 10
    private lateinit var assertionObjects: List<GetAssertionSession.AssertionObject>

    // initialized in Step 11/12
    private lateinit var onGoingGetAssertionSession: GetAssertionSession

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
        this.authenticationExtensionsAuthenticatorInputs = authenticatorGetAssertionRequest.extensions
        this.options = authenticatorGetAssertionRequest.options
        this.pinUvAuthParam = authenticatorGetAssertionRequest.pinUvAuthParam
        this.pinUvAuthProtocol = authenticatorGetAssertionRequest.pinUvAuthProtocol
        // Default to the highest version protocol (list is sorted by version descending).
        // Overridden in Step 2 when pinUvAuthParam is present.
        this.protocol = ctapAuthenticatorSession.pinUvAuthManager.pinUvAuthProtocols.first()
    }

    override suspend fun validate() {
        getAssertionRequestValidator.validate(authenticatorGetAssertionRequest)
    }

    override suspend fun doExecute(): AuthenticatorGetAssertionResponse {
        ctapAuthenticatorSession.onGoingGetAssertionSession = null

        execStep1ZeroLengthPinUvAuthParam()
        execStep2ValidatePinUvAuthProtocol()
        // TODO: Step 3: Create a new response structure. Currently represented by field declarations (upResult=false, uvResult=false).
        execStep4ProcessOptions()
        execStep5ProcessAlwaysUv()
        execStep6ProcessUserVerification()
        execStep7LocateCredentials()
        execStep8SetUserPresenceFromBuiltInUv()
        if (!uvState) {
            execStep9TestUserPresence()
        }
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
    //spec|   1.1 Request evidence of user interaction in an authenticator-specific way (e.g., flash the LED light).
    //spec|   1.2 If the user declines permission, or the operation times out, then end the operation by returning CTAP2_ERR_OPERATION_DENIED.
    //spec|   1.3 If evidence of user interaction is provided in this step then return either
    //spec|   CTAP2_ERR_PIN_NOT_SET if PIN is not set or CTAP2_ERR_PIN_INVALID if PIN has been set.
    //
    // @see https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-getAssert-authnr-alg
    private suspend fun execStep1ZeroLengthPinUvAuthParam() {
        //spec| Step 1. If authenticator supports either pinUvAuthToken or clientPin features and the platform sends a zero length pinUvAuthParam:
        if (pinUvAuthParam != null && pinUvAuthParam.isEmpty()) {
            //spec| 1.1 Request evidence of user interaction in an authenticator-specific way (e.g., flash the LED light).
            //spec| 1.2 If the user declines permission, or the operation times out, then end the operation by returning CTAP2_ERR_OPERATION_DENIED.
            if (!performBuiltInUp()) {
                throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_OPERATION_DENIED)
            }
            //spec| 1.3 If evidence of user interaction is provided in this step then return either
            //spec| CTAP2_ERR_PIN_NOT_SET if PIN is not set or CTAP2_ERR_PIN_INVALID if PIN has been set.
            if (ctapAuthenticatorSession.isClientPINReady) {
                throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_PIN_INVALID)
            } else {
                throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_PIN_NOT_SET)
            }
        }
    }

    //spec| Step 2. If the pinUvAuthParam parameter is present:
    //spec|   2.1 If the pinUvAuthProtocol parameter's value is not supported, return CTAP1_ERR_INVALID_PARAMETER error.
    //spec|   2.2 If the pinUvAuthProtocol parameter is absent, return CTAP2_ERR_MISSING_PARAMETER error.
    //
    // @see https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-getAssert-authnr-alg
    private fun execStep2ValidatePinUvAuthProtocol() {
        //spec| Step 2. If the pinUvAuthParam parameter is present:
        if (pinUvAuthParam != null) {
            if (pinUvAuthProtocol != null) {
                //spec| 2.1 If the pinUvAuthProtocol parameter's value is not supported, return CTAP1_ERR_INVALID_PARAMETER error.
                protocol = ctapAuthenticatorSession.pinUvAuthManager.pinUvAuthProtocols
                    .firstOrNull { it.version == pinUvAuthProtocol }
                    ?: throw CtapCommandExecutionException(CtapStatusCode.CTAP1_ERR_INVALID_PARAMETER)
            } else {
                //spec| 2.2 If the pinUvAuthProtocol parameter is absent, return CTAP2_ERR_MISSING_PARAMETER error.
                throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_MISSING_PARAMETER)
            }
        }
    }

    //spec| Step 4. If the options parameter is present, process all option keys and values present in the parameter. Treat any option keys that are not understood as absent.
    //spec|   4.1 If the "uv" option is absent, let the "uv" option be treated as being present with the value false. (This is the default)
    //spec|   4.2 If the pinUvAuthParam is present, let the "uv" option be treated as being present with the value false.
    //spec|   4.3 If the "uv" option is present and true then:
    //spec|     4.3.1 If the authenticator does not support a built-in user verification method end the operation by returning CTAP2_ERR_INVALID_OPTION.
    //spec|     4.3.2 If the built-in user verification method has not yet been enabled, end the operation by returning CTAP2_ERR_INVALID_OPTION.
    //spec|   4.4 If the "rk" option is present then:
    //spec|     4.4.1 Return CTAP2_ERR_UNSUPPORTED_OPTION.
    //spec|   4.5 If the "up" option is not present then:
    //spec|     4.5.1 Let the "up" option be treated as being present with the value true. (This is the default)
    //
    // @see https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-getAssert-authnr-alg
    private fun execStep4ProcessOptions() {
        val requestOptions = options

        //spec| 4.1 If the "uv" option is absent, let the "uv" option be treated as being present with the value false. (This is the default)
        var uv = requestOptions?.uv ?: false
        //spec| 4.2 If the pinUvAuthParam is present, let the "uv" option be treated as being present with the value false.
        if (pinUvAuthParam != null) {
            uv = false
        }
        //spec| 4.3 If the "uv" option is present and true then:
        if (uv) {
            when (ctapAuthenticatorSession.userVerification) {
                //spec| 4.3.1 If the authenticator does not support a built-in user verification method end the operation by returning CTAP2_ERR_INVALID_OPTION.
                UserVerificationSetting.NOT_SUPPORTED -> throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_INVALID_OPTION)
                //spec| 4.3.2 If the built-in user verification method has not yet been enabled, end the operation by returning CTAP2_ERR_INVALID_OPTION.
                UserVerificationSetting.NOT_READY -> throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_INVALID_OPTION)
                UserVerificationSetting.READY -> {}
            }
        }
        shouldPerformUv = uv

        //spec| 4.4 If the "rk" option is present then:
        //spec|   4.4.1 Return CTAP2_ERR_UNSUPPORTED_OPTION.
        if (requestOptions?.rk != null) {
            throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_UNSUPPORTED_OPTION)
        }

        //spec| 4.5 If the "up" option is not present then:
        //spec|   4.5.1 Let the "up" option be treated as being present with the value true. (This is the default)
        val up = requestOptions?.up ?: true
        // Implementation-specific: reject up=true when the authenticator does not support user presence.
        // The spec does not explicitly define this check, but an authenticator that cannot perform UP
        // cannot fulfill the request.
        if (up) {
            shouldPerformUp = when (ctapAuthenticatorSession.userPresence) {
                UserPresenceSetting.SUPPORTED -> true
                else -> throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_UNSUPPORTED_OPTION)
            }
        } else {
            shouldPerformUp = false
        }
    }

    //spec| Step 5. If the alwaysUv option ID is present and true and the "up" option is present and true then:
    //spec|   5.1 If the authenticator is not protected by some form of user verification:
    //spec|     5.1.1 If the clientPin option ID is present and noMcGaPermissionsWithClientPin option ID is absent or false (clientPin is supported for the ga permission):
    //spec|       5.1.1.1 End the operation by returning CTAP2_ERR_PUAT_REQUIRED.
    //spec|     5.1.2 Else (clientPin is not supported):
    //spec|       5.1.2.1 End the operation by returning CTAP2_ERR_OPERATION_DENIED.
    //spec|   5.2 If the pinUvAuthParam is present then go to Step 6.
    //spec|   5.3 If the "uv" option is true then go to Step 6.
    //spec|   5.4 If the "uv" option is false and the authenticator supports a built-in user verification method, and the user verification method is enabled then:
    //spec|     5.4.1 Let the "uv" option be treated as being present with the value true.
    //spec|     5.4.2 Go To Step 6.
    //spec|   5.5 If the clientPin option ID is present and noMcGaPermissionsWithClientPin option ID is absent or false, then:
    //spec|     5.5.1 End the operation by returning CTAP2_ERR_PUAT_REQUIRED.
    //spec|   5.6 Else (clientPin is not supported):
    //spec|     5.6.1 End the operation by returning CTAP2_ERR_OPERATION_DENIED.
    //
    // @see https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-getAssert-authnr-alg
    private fun execStep5ProcessAlwaysUv() {
        //spec| Step 5. If the alwaysUv option ID is present and true and the "up" option is present and true then:
        if (ctapAuthenticatorSession.alwaysUv == AlwaysUvSetting.ENABLED && shouldPerformUp) {
            //spec| 5.1 If the authenticator is not protected by some form of user verification:
            if (!isProtectedByUserVerification) {
                //spec| 5.1.1 If the clientPin option ID is present and noMcGaPermissionsWithClientPin option ID is absent or false (clientPin is supported for the ga permission):
                // TODO: noMcGaPermissionsWithClientPin not yet implemented; always treated as absent
                if (ctapAuthenticatorSession.clientPIN == ClientPINSetting.ENABLED) {
                    //spec| 5.1.1.1 End the operation by returning CTAP2_ERR_PUAT_REQUIRED.
                    throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_PUAT_REQUIRED)
                }
                //spec| 5.1.2 Else (clientPin is not supported):
                else {
                    //spec| 5.1.2.1 End the operation by returning CTAP2_ERR_OPERATION_DENIED.
                    throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_OPERATION_DENIED)
                }
            }

            //spec| 5.2 If the pinUvAuthParam is present then go to Step 6.
            if (pinUvAuthParam != null) {
                return
            }

            //spec| 5.3 If the "uv" option is true then go to Step 6.
            if (shouldPerformUv) {
                return
            }

            //spec| 5.4 If the "uv" option is false and the authenticator supports a built-in user verification method, and the user verification method is enabled then:
            if (!shouldPerformUv && ctapAuthenticatorSession.userVerification == UserVerificationSetting.READY) {
                //spec| 5.4.1 Let the "uv" option be treated as being present with the value true.
                shouldPerformUv = true
                //spec| 5.4.2 Go To Step 6.
                return
            }

            //spec| 5.5 If the clientPin option ID is present and noMcGaPermissionsWithClientPin option ID is absent or false, then:
            // TODO: noMcGaPermissionsWithClientPin not yet implemented; always treated as absent
            if (ctapAuthenticatorSession.clientPIN == ClientPINSetting.ENABLED) {
                //spec| 5.5.1 End the operation by returning CTAP2_ERR_PUAT_REQUIRED.
                throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_PUAT_REQUIRED)
            }
            //spec| 5.6 Else (clientPin is not supported):
            else {
                //spec| 5.6.1 End the operation by returning CTAP2_ERR_OPERATION_DENIED.
                throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_OPERATION_DENIED)
            }
        }
    }

    //spec| Step 6. If the authenticator is protected by some form of user verification, then:
    //spec|   6.1 If pinUvAuthParam parameter is present (implying the "uv" option is treated as false, see Step 4):
    //spec|     6.1.1 Call verify(pinUvAuthToken, clientDataHash, pinUvAuthParam).
    //spec|       6.1.1.1 If the verification returns error, return CTAP2_ERR_PIN_AUTH_INVALID error.
    //spec|       6.1.1.2 If the verification returns success, set the "uv" bit to true in the response.
    //spec|     6.1.2 Let userVerifiedFlagValue be the result of calling getUserVerifiedFlagValue().
    //spec|     6.1.3 If userVerifiedFlagValue is false then end the operation by returning CTAP2_ERR_PIN_AUTH_INVALID.
    //spec|     6.1.4 Verify that the pinUvAuthToken has the ga permission, if not, return CTAP2_ERR_PIN_AUTH_INVALID.
    //spec|     6.1.5 If the pinUvAuthToken has a permissions RP ID associated:
    //spec|       6.1.5.1 If the permissions RP ID does not match the rpId in this request, return CTAP2_ERR_PIN_AUTH_INVALID.
    //spec|     6.1.6 If the pinUvAuthToken does not have a permissions RP ID associated:
    //spec|       6.1.6.1 Associate the request's rpId parameter value with the pinUvAuthToken as its permissions RP ID.
    //spec|     6.1.7 Go to Step 7.
    //spec|   6.2 If the "uv" option is present and set to true (implying the pinUvAuthParam parameter is not present,
    //spec|   and that the authenticator supports an enabled built-in user verification method, see Step 4):
    //spec|     6.2.1 Let internalRetry be true.
    //spec|     6.2.2 Let uvState be the result of calling performBuiltInUv(internalRetry)
    //spec|     6.2.3 If uvState is error:
    //spec|       6.2.3.1 If the error reason is a user action timeout, then return CTAP2_ERR_USER_ACTION_TIMEOUT.
    //spec|       6.2.3.2 If the ClientPin option ID is true and the noMcGaPermissionsWithClientPin option ID is absent or false, end the operation by returning CTAP2_ERR_PUAT_REQUIRED.
    //spec|       6.2.3.3 If the uvRetries counter is 0, return CTAP2_ERR_PIN_BLOCKED.
    //spec|       6.2.3.4 Otherwise, end the operation by returning CTAP2_ERR_OPERATION_DENIED.
    //spec|     6.2.4 If uvState is success:
    //spec|       6.2.4.1 Set the "uv" bit to true in the response.
    //
    // @see https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-getAssert-authnr-alg
    private suspend fun execStep6ProcessUserVerification() {
        //spec| Step 6. If the authenticator is protected by some form of user verification, then:
        if (isProtectedByUserVerification) {
            //spec| 6.1 If pinUvAuthParam parameter is present (implying the "uv" option is treated as false, see Step 4):
            if (pinUvAuthParam != null) {
                //spec| 6.1.1 Call verify(pinUvAuthToken, clientDataHash, pinUvAuthParam).
                if (!protocol.verify(protocol.pinUvAuthToken, clientDataHash, pinUvAuthParam)) {
                    //spec| 6.1.1.1 If the verification returns error, return CTAP2_ERR_PIN_AUTH_INVALID error.
                    throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_PIN_AUTH_INVALID)
                }
                //spec| 6.1.1.2 If the verification returns success, set the "uv" bit to true in the response.
                uvResult = true

                //spec| 6.1.2 Let userVerifiedFlagValue be the result of calling getUserVerifiedFlagValue().
                val userVerifiedFlagValue = protocol.tokenState.getUserVerifiedFlagValue()
                //spec| 6.1.3 If userVerifiedFlagValue is false then end the operation by returning CTAP2_ERR_PIN_AUTH_INVALID.
                if (!userVerifiedFlagValue) {
                    throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_PIN_AUTH_INVALID)
                }

                //spec| 6.1.4 Verify that the pinUvAuthToken has the ga permission, if not, return CTAP2_ERR_PIN_AUTH_INVALID.
                if (!protocol.tokenState.hasPermission(PinUvAuthTokenPermission.GA)) {
                    throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_PIN_AUTH_INVALID)
                }

                //spec| 6.1.5 If the pinUvAuthToken has a permissions RP ID associated:
                //spec|   6.1.5.1 If the permissions RP ID does not match the rpId in this request, return CTAP2_ERR_PIN_AUTH_INVALID.
                val tokenRpId = protocol.tokenState.permissionsRpId
                if (tokenRpId != null && tokenRpId != rpId) {
                    throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_PIN_AUTH_INVALID)
                }

                //spec| 6.1.6 If the pinUvAuthToken does not have a permissions RP ID associated:
                //spec|   6.1.6.1 Associate the request's rpId parameter value with the pinUvAuthToken as its permissions RP ID.
                if (protocol.tokenState.permissionsRpId == null) {
                    protocol.tokenState.permissionsRpId = rpId
                }

                // Record token usage to prevent expiration by initial usage time limit (§6.5.2.1)
                protocol.tokenState.recordTokenUsage()
                //spec| 6.1.7 Go to Step 7.
                return
            }

            //spec| 6.2 If the "uv" option is present and set to true (implying the pinUvAuthParam parameter is not present,
            //spec| and that the authenticator supports an enabled built-in user verification method, see Step 4):
            if (shouldPerformUv) {
                //spec| 6.2.1 Let internalRetry be true.
                //spec| 6.2.2 Let uvState be the result of calling performBuiltInUv(internalRetry)
                uvState = performBuiltInUv()
                if (!uvState) {
                    //spec| 6.2.3 If uvState is error:
                    //spec|   6.2.3.1 If the error reason is a user action timeout, then return CTAP2_ERR_USER_ACTION_TIMEOUT.
                    //spec|   6.2.3.2 If the ClientPin option ID is true and the noMcGaPermissionsWithClientPin option ID is absent or false, end the operation by returning CTAP2_ERR_PUAT_REQUIRED.
                    //spec|   6.2.3.3 If the uvRetries counter is 0, return CTAP2_ERR_PIN_BLOCKED.
                    //spec|   6.2.3.4 Otherwise, end the operation by returning CTAP2_ERR_OPERATION_DENIED.
                    // Simplified: performBuiltInUv() returns a boolean; detailed error reasons
                    // (timeout, blocked, PUAT) are not yet distinguished.
                    throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_OPERATION_DENIED)
                } else {
                    //spec| 6.2.4 If uvState is success:
                    //spec|   6.2.4.1 Set the "uv" bit to true in the response.
                    uvResult = true
                }
            }
        }
    }

    //spec| Step 7. Locate all credentials that are eligible for retrieval under the specified criteria:
    //spec|   7.1 If the allowList parameter is present and is non-empty, locate all denoted credentials created by this authenticator and bound to the specified rpId.
    //spec|   7.2 If an allowList is not present, locate all discoverable credentials that are created by this authenticator and bound to the specified rpId.
    //spec|   7.3 Create an applicable credentials list populated with the located credentials.
    //spec|   7.4 Iterate through the applicable credentials list, and if credential protection for a credential is marked as userVerificationRequired, and the "uv" bit is false in the response, remove that credential from the applicable credentials list.
    //spec|   7.5 Iterate through the applicable credentials list, and if credential protection for a credential is marked as userVerificationOptionalWithCredentialIDList and there is no allowList passed by the client and the "uv" bit is false in the response, remove that credential from the applicable credentials list.
    //spec|   7.6 If the applicable credentials list is empty, return CTAP2_ERR_NO_CREDENTIALS.
    //spec|   7.7 Let numberOfCredentials be the number of applicable credentials found.
    //
    // @see https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-getAssert-authnr-alg
    private fun execStep7LocateCredentials() {
        //spec| 7.1 If the allowList parameter is present and is non-empty, locate all denoted credentials created by this authenticator and bound to the specified rpId.
        //spec| 7.2 If an allowList is not present, locate all discoverable credentials that are created by this authenticator and bound to the specified rpId.
        //spec| 7.3 Create an applicable credentials list populated with the located credentials.
        credentials = if (allowList != null && allowList.isNotEmpty()) {
            val storedCredentials = authenticatorPropertyStore.loadUserCredentials(rpId)
                .filter {
                    allowList.any { allowed: PublicKeyCredentialDescriptor ->
                        it.credentialId.contentEquals(allowed.id)
                    }
                }.filter { it.rpIdHash.contentEquals(rpIdHash) }
            val derivedCredentials = allowList.mapNotNull(this::deriveCredential)
            val result: MutableList<Credential> = ArrayList()
            result.addAll(storedCredentials)
            result.addAll(derivedCredentials)
            result
        } else {
            ArrayList<Credential>(authenticatorPropertyStore.loadUserCredentials(rpId))
        }

        //spec| 7.4 Iterate through the applicable credentials list, and if credential protection for a credential is marked as userVerificationRequired, and the "uv" bit is false in the response, remove that credential from the applicable credentials list.
        //spec| 7.5 Iterate through the applicable credentials list, and if credential protection for a credential is marked as userVerificationOptionalWithCredentialIDList and there is no allowList passed by the client and the "uv" bit is false in the response, remove that credential from the applicable credentials list.
        // Actual filtering logic is delegated to GetAssertionCredentialFilter implementations (e.g., CredProtectExtensionProcessor).
        val credentialFilters = ctapAuthenticatorSession.extensionProcessors
            .filterIsInstance<GetAssertionCredentialFilter>()
        if (credentialFilters.isNotEmpty()) {
            credentials = credentials.filter { credential ->
                val context = GetAssertionCredentialFilterContext(authenticatorGetAssertionRequest, credential, uvResult)
                credentialFilters.all { it.test(context) }
            }
        }

        //spec| 7.6 If the applicable credentials list is empty, return CTAP2_ERR_NO_CREDENTIALS.
        if (credentials.isEmpty()) {
            throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_NO_CREDENTIALS)
        }

        //spec| 7.7 Let numberOfCredentials be the number of applicable credentials found.
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
                EC2COSEKey.create(
                    KeyPair(u2fKeyEnvelope.keyPair.publicKey!!, u2fKeyEnvelope.keyPair.privateKey!!),
                    COSEAlgorithmIdentifier.ES256
                )
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
    //spec|   8.1 Set the "up" bit to true in the response.
    //spec|   8.2 Go to Step 10
    //
    // @see https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-getAssert-authnr-alg
    private fun execStep8SetUserPresenceFromBuiltInUv() {
        //spec| Step 8. If evidence of user interaction was provided as part of Step 6.2 (i.e., by invoking performBuiltInUv()):
        if (uvState) {
            //spec| 8.1 Set the "up" bit to true in the response.
            upResult = true
            //spec| 8.2 Go to Step 10
        }
    }

    //spec| Step 9. If the "up" option is set to true or not present:
    //spec|   9.1 If the pinUvAuthParam parameter is present then:
    //spec|     9.1.1 Let userPresentFlagValue be the result of calling getUserPresentFlagValue().
    //spec|     9.1.2 If userPresentFlagValue is false:
    //spec|       9.1.2.1 Request evidence of user interaction in an authenticator-specific way (e.g., flash the LED light).
    //spec|       If the authenticator has a display, show the rpId parameter value to the user,
    //spec|       and request permission to create an assertion.
    //spec|       9.1.2.2 If the user declines permission, or the operation times out, then end the operation by returning CTAP2_ERR_OPERATION_DENIED.
    //spec|   9.2 Else (implying the pinUvAuthParam parameter is not present):
    //spec|     9.2.1 If the "up" bit is false in the response:
    //spec|       9.2.1.1 Request evidence of user interaction in an authenticator-specific way (e.g., flash the LED light).
    //spec|       If the authenticator has a display, show the rpId parameter value to the user,
    //spec|       and request permission to create an assertion.
    //spec|       9.2.1.2 If the user declines permission, or the operation times out, then end the operation by returning CTAP2_ERR_OPERATION_DENIED.
    //spec|   9.3 Set the "up" bit to true in the response.
    //spec|   9.4 Call clearUserPresentFlag(), clearUserVerifiedFlag(), and clearPinUvAuthTokenPermissionsExceptLbw().
    //
    // @see https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-getAssert-authnr-alg
    private suspend fun execStep9TestUserPresence() {
        //spec| Step 9. If the "up" option is set to true or not present:
        if (shouldPerformUp) {
            //spec| 9.1 If the pinUvAuthParam parameter is present then:
            if (pinUvAuthParam != null) {
                //spec| 9.1.1 Let userPresentFlagValue be the result of calling getUserPresentFlagValue().
                val userPresentFlagValue = protocol.tokenState.getUserPresentFlagValue()
                //spec| 9.1.2 If userPresentFlagValue is false:
                if (!userPresentFlagValue) {
                    //spec| 9.1.2.1 Request evidence of user interaction in an authenticator-specific way (e.g., flash the LED light).
                    //spec| If the authenticator has a display, show the rpId parameter value to the user,
                    //spec| and request permission to create an assertion.
                    //spec| 9.1.2.2 If the user declines permission, or the operation times out, then end the operation by returning CTAP2_ERR_OPERATION_DENIED.
                    if (!performBuiltInUp()) {
                        throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_OPERATION_DENIED)
                    }
                }
            } else {
                //spec| 9.2 Else (implying the pinUvAuthParam parameter is not present):
                //spec|   9.2.1 If the "up" bit is false in the response:
                if (!upResult) {
                    //spec| 9.2.1.1 Request evidence of user interaction in an authenticator-specific way (e.g., flash the LED light).
                    //spec| If the authenticator has a display, show the rpId parameter value to the user,
                    //spec| and request permission to create an assertion.
                    //spec| 9.2.1.2 If the user declines permission, or the operation times out, then end the operation by returning CTAP2_ERR_OPERATION_DENIED.
                    if (!performBuiltInUp()) {
                        throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_OPERATION_DENIED)
                    }
                }
            }

            //spec| 9.3 Set the "up" bit to true in the response.
            upResult = true

            //spec| 9.4 Call clearUserPresentFlag(), clearUserVerifiedFlag(), and clearPinUvAuthTokenPermissionsExceptLbw().
            protocol.tokenState.clearUserPresentFlag()
            protocol.tokenState.clearUserVerifiedFlag()
            protocol.tokenState.clearPinUvAuthTokenPermissionsExceptLbw()
        }
    }

    private suspend fun performBuiltInUv(): Boolean {
        val request = GetAssertionConsentRequest(rpId, isUserPresence = true, isUserVerification = true)
        return ctapAuthenticatorSession.withUserPresenceWait {
            ctapAuthenticatorSession.getAssertionConsentHandler.onGetAssertionConsentRequested(request)
        }
    }

    private suspend fun performBuiltInUp(): Boolean {
        val request = GetAssertionConsentRequest(rpId, isUserPresence = true, isUserVerification = false)
        return ctapAuthenticatorSession.withUserPresenceWait {
            ctapAuthenticatorSession.getAssertionConsentHandler.onGetAssertionConsentRequested(request)
        }
    }

    //spec| Step 10. If the extensions parameter is present:
    //spec|   10.1 Process any extensions that this authenticator supports, ignoring any that it does not support.
    //spec|   10.2 Authenticator extension outputs generated by the authenticator extension processing
    //spec|   are returned in the authenticator data. The set of keys in the authenticator extension outputs map MUST be equal to,
    //spec|   or a subset of, the keys of the authenticator extension inputs map.
    //
    // @see https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-getAssert-authnr-alg
    private fun execStep10ProcessExtensions() {
        val inputs = this.authenticationExtensionsAuthenticatorInputs
        assertionObjects = credentials.map { credential ->
            val outputsBuilder =
                AuthenticationExtensionsAuthenticatorOutputs.BuilderForAuthentication()
            if (inputs != null) {
                //spec| 10.1 Process any extensions that this authenticator supports, ignoring any that it does not support.
                val context = AuthenticationExtensionContext(
                    ctapAuthenticatorSession,
                    authenticatorGetAssertionRequest,
                    credential,
                    shouldPerformUv,
                    shouldPerformUp
                )
                ctapAuthenticatorSession.extensionProcessors.filterIsInstance<AuthenticationExtensionProcessor>()
                    .forEach { processor ->
                        if (processor.supportsAuthenticationExtension(inputs)) {
                            processor.processAuthenticationExtension(context, outputsBuilder)
                        }
                    }
            }
            //spec| 10.2 Authenticator extension outputs generated by the authenticator extension processing
            //spec| are returned in the authenticator data. The set of keys in the authenticator extension outputs map MUST be equal to,
            //spec| or a subset of, the keys of the authenticator extension inputs map.
            GetAssertionSession.AssertionObject(credential, false, outputsBuilder.build(), 0)
        }
    }

    //spec| Step 11. If the allowList parameter is present:
    //spec|   11.1 Select any credential from the applicable credentials list.
    //spec|   11.2 Delete the numberOfCredentials member.
    //spec|   11.3 Go to Step 13.
    //spec| Step 12. If allowList is not present:
    //spec|   12.1 If numberOfCredentials is one:
    //spec|     12.1.1 Select that credential.
    //spec|   12.2 If numberOfCredentials is more than one:
    //spec|     12.2.1 Order the credentials in the applicable credentials list by the time when they were created in reverse order.
    //spec|     (I.e. the first credential is the most recently created.)
    //spec|     12.2.2 If the authenticator does not have a display, or the authenticator does have a display and the "uv" and "up" options are false:
    //spec|       12.2.2.1 Remember the authenticatorGetAssertion parameters.
    //spec|       12.2.2.2 Create a credential counter (credentialCounter) and set it to 1.
    //spec|       This counter signifies the next credential to be returned by the authenticator, assuming zero-based indexing.
    //spec|       12.2.2.3 Start a timer. This is used during authenticatorGetNextAssertion command. This step is OPTIONAL if transport is done over NFC.
    //spec|       12.2.2.4 Select the first credential.
    //spec|     12.2.3 If the authenticator has a display and at least one of the "uv" and "up" options is true:
    //spec|       12.2.3.1 Display all the credentials in the applicable credentials list to the user, using their friendly name along with other stored account information.
    //spec|       12.2.3.2 Also, display the rpId of the requester (specified in the request) and ask the user to select a credential.
    //spec|       12.2.3.3 If the user declines to select a credential or takes too long (as determined by the authenticator), terminate this procedure and return the CTAP2_ERR_OPERATION_DENIED error.
    //spec|       12.2.3.4 Update the response to set the userSelected member to true and to delete the numberOfCredentials member.
    //spec|       12.2.3.5 Select the credential indicated by the user.
    //spec|   12.3 Update the response to include the selected credential's publicKeyCredentialUserEntity information.
    //spec|   User identifiable information (name, DisplayName, icon) inside the publicKeyCredentialUserEntity MUST NOT be returned if user verification is not done by the authenticator.
    //
    // @see https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-getAssert-authnr-alg
    private suspend fun execStep11And12SelectCredential() {
        // Build authenticator data flags from uv/up results
        var flags: Byte = 0
        if (uvResult) {
            flags = flags or AuthenticatorData.BIT_UV
        }
        if (upResult) {
            flags = flags or AuthenticatorData.BIT_UP
        }
        assertionObjects.forEach { assertionObject ->
            assertionObject.flags = flags
            if (assertionObject.extensions.keys.isNotEmpty()) {
                assertionObject.flags = assertionObject.flags or AuthenticatorData.BIT_ED
            }
        }

        //spec| Step 11. If the allowList parameter is present:
        if (allowList != null && allowList.isNotEmpty()) {
            //spec| 11.1 Select any credential from the applicable credentials list.
            onGoingGetAssertionSession = GetAssertionSession(assertionObjects, clientDataHash)
            ctapAuthenticatorSession.onGoingGetAssertionSession = onGoingGetAssertionSession
            //spec| 11.2 Delete the numberOfCredentials member.
            suppressNumberOfCredentials = true
            //spec| 11.3 Go to Step 13.
        }
        //spec| Step 12. If allowList is not present:
        else {
            val numberOfCredentials = assertionObjects.size
            //spec| 12.1 If numberOfCredentials is one:
            if (numberOfCredentials == 1) {
                //spec| 12.1.1 Select that credential.
                onGoingGetAssertionSession = GetAssertionSession(assertionObjects, clientDataHash)
                ctapAuthenticatorSession.onGoingGetAssertionSession = onGoingGetAssertionSession
            }
            //spec| 12.2 If numberOfCredentials is more than one:
            else if (numberOfCredentials > 1) {
                //spec| 12.2.1 Order the credentials in the applicable credentials list by the time when they were created in reverse order.
                //spec| (I.e. the first credential is the most recently created.)
                assertionObjects = assertionObjects.sortedByDescending { it.credential.createdAt.epochSecond }

                //spec| 12.2.2 If the authenticator does not have a display, or the authenticator does have a display and the "uv" and "up" options are false:
                if (ctapAuthenticatorSession.credentialSelector != CredentialSelectorSetting.AUTHENTICATOR || (!shouldPerformUv && !shouldPerformUp)) {
                    //spec| 12.2.2.1 Remember the authenticatorGetAssertion parameters.
                    //spec| 12.2.2.2 Create a credential counter (credentialCounter) and set it to 1.
                    //spec| This counter signifies the next credential to be returned by the authenticator, assuming zero-based indexing.
                    //spec| 12.2.2.3 Start a timer. This is used during authenticatorGetNextAssertion command. This step is OPTIONAL if transport is done over NFC.
                    //spec| 12.2.2.4 Select the first credential.
                    onGoingGetAssertionSession = GetAssertionSession(assertionObjects, clientDataHash)
                    ctapAuthenticatorSession.onGoingGetAssertionSession = onGoingGetAssertionSession
                }
                //spec| 12.2.3 If the authenticator has a display and at least one of the "uv" and "up" options is true:
                else {
                    //spec| 12.2.3.1 Display all the credentials in the applicable credentials list to the user, using their friendly name along with other stored account information.
                    //spec| 12.2.3.2 Also, display the rpId of the requester (specified in the request) and ask the user to select a credential.
                    //spec| 12.2.3.3 If the user declines to select a credential or takes too long (as determined by the authenticator), terminate this procedure and return the CTAP2_ERR_OPERATION_DENIED error.
                    val selectedCredential: Credential
                    try {
                        selectedCredential = ctapAuthenticatorSession.credentialSelectionHandler.onSelect(credentials)
                    } catch (e: CredentialSelectionCanceledException) {
                        throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_OPERATION_DENIED, e)
                    }
                    val selectedAssertionObject =
                        assertionObjects.find { it.credential.credentialId.contentEquals(selectedCredential.credentialId) }
                            ?: throw IllegalStateException("Selected Credential is not found in AssertionObject list")
                    //spec| 12.2.3.4 Update the response to set the userSelected member to true and to delete the numberOfCredentials member.
                    userSelected = true
                    suppressNumberOfCredentials = true
                    //spec| 12.2.3.5 Select the credential indicated by the user.
                    onGoingGetAssertionSession = GetAssertionSession(listOf(selectedAssertionObject), clientDataHash)
                    ctapAuthenticatorSession.onGoingGetAssertionSession = onGoingGetAssertionSession
                }
            }

            //spec| 12.3 Update the response to include the selected credential's publicKeyCredentialUserEntity information.
            //spec| User identifiable information (name, DisplayName, icon) inside the publicKeyCredentialUserEntity MUST NOT be returned if user verification is not done by the authenticator.
            if (!uvResult) {
                onGoingGetAssertionSession.assertionObjects.forEach {
                    it.maskUserIdentifiableInfo = true
                }
            }
        }
    }

    //spec| Step 13. Sign the clientDataHash along with authData with the selected credential, using the structure specified in [WebAuthn].
    //
    // @see https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-getAssert-authnr-alg
    private fun execStep13Sign(): AuthenticatorGetAssertionResponse {
        //spec| Step 13. Sign the clientDataHash along with authData with the selected credential, using the structure specified in [WebAuthn].
        val assertionObject = onGoingGetAssertionSession.currentAssertionObject()
        onGoingGetAssertionSession.incrementCredentialCounter()
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
        val numberOfCredentials = if (suppressNumberOfCredentials) null else onGoingGetAssertionSession.numberOfAssertionObjects

        val responseData = AuthenticatorGetAssertionResponseData(
            descriptor,
            authData,
            signature,
            user,
            numberOfCredentials,
            if (userSelected) true else null
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
