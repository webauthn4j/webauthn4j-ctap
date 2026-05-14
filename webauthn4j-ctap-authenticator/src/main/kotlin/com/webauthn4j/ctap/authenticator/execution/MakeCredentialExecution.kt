package com.webauthn4j.ctap.authenticator.execution


import com.webauthn4j.ctap.authenticator.CtapAuthenticatorSession
import com.webauthn4j.ctap.authenticator.MakeCredentialConsentRequest
import com.webauthn4j.ctap.authenticator.PinUvAuthProtocol
import com.webauthn4j.ctap.authenticator.UserCredentialBuilder
import com.webauthn4j.ctap.authenticator.attestation.AttestationStatementRequest
import com.webauthn4j.ctap.authenticator.data.credential.CredentialKey
import com.webauthn4j.ctap.authenticator.data.credential.NonResidentCredentialKey
import com.webauthn4j.ctap.authenticator.data.credential.NonResidentUserCredentialSource
import com.webauthn4j.ctap.authenticator.data.credential.ResidentUserCredential
import com.webauthn4j.ctap.authenticator.data.credential.UserCredential
import com.webauthn4j.ctap.authenticator.data.event.MakeCredentialEvent
import com.webauthn4j.ctap.authenticator.extension.MakeCredentialCredentialFilter
import com.webauthn4j.ctap.authenticator.extension.MakeCredentialCredentialFilterContext
import com.webauthn4j.ctap.authenticator.data.settings.AlwaysUvSetting
import com.webauthn4j.ctap.authenticator.data.settings.ClientPINSetting
import com.webauthn4j.ctap.authenticator.data.settings.MakeCredUvNotRqdSetting
import com.webauthn4j.ctap.authenticator.data.settings.ResidentKeySetting
import com.webauthn4j.ctap.authenticator.data.settings.UserPresenceSetting
import com.webauthn4j.ctap.authenticator.data.settings.UserVerificationSetting
import com.webauthn4j.ctap.authenticator.extension.RegistrationExtensionContext
import com.webauthn4j.ctap.authenticator.extension.RegistrationExtensionProcessor
import com.webauthn4j.ctap.authenticator.internal.KeyPairUtil.createCredentialKeyPair
import com.webauthn4j.ctap.authenticator.store.AuthenticatorPropertyStore
import com.webauthn4j.ctap.authenticator.store.StoreFullException
import com.webauthn4j.ctap.core.data.*
import com.webauthn4j.ctap.core.data.PinUvAuthTokenPermission
import com.webauthn4j.data.PinProtocolVersion
import java.util.Arrays
import com.webauthn4j.ctap.core.util.internal.CipherUtil
import com.webauthn4j.ctap.core.validator.AuthenticatorMakeCredentialRequestValidator
import com.webauthn4j.data.PublicKeyCredentialDescriptor
import com.webauthn4j.data.PublicKeyCredentialParameters
import com.webauthn4j.data.PublicKeyCredentialType
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData
import com.webauthn4j.data.attestation.authenticator.COSEKey
import com.webauthn4j.data.attestation.statement.AttestationStatement
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorInputs
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorOutputs
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorInput
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorOutput
import com.webauthn4j.util.MessageDigestUtil
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.nio.charset.StandardCharsets
import java.security.SecureRandom
import java.time.Instant
import java.util.*
import kotlin.experimental.or

/**
 * MakeCredential command execution
 *
 * @see <a href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-makeCred-authnr-alg">CTAP 2.3 §6.1.2 authenticatorMakeCredential Algorithm</a>
 */
@Suppress("ConvertSecondaryConstructorToPrimary", "FunctionName")
internal class MakeCredentialExecution :
    CtapCommandExecutionBase<AuthenticatorMakeCredentialRequest, AuthenticatorMakeCredentialResponse> {

    override val commandName: String = "MakeCredential"

    private val logger: Logger = LoggerFactory.getLogger(MakeCredentialExecution::class.java)
    private val makeCredentialRequestValidator = AuthenticatorMakeCredentialRequestValidator()

    @Suppress("JoinDeclarationAndAssignment")
    private val ctapAuthenticatorSession: CtapAuthenticatorSession
    private val authenticatorMakeCredentialRequest: AuthenticatorMakeCredentialRequest

    private val authenticatorPropertyStore: AuthenticatorPropertyStore
    private val secureRandom = SecureRandom()

    // command properties
    private val clientDataHash: ByteArray
    private val rp: CtapPublicKeyCredentialRpEntity
    private val rpId: String
    private val user: CtapPublicKeyCredentialUserEntity
    private val pubKeyCredParams: List<PublicKeyCredentialParameters>
    private val excludeList: List<PublicKeyCredentialDescriptor>?
    private val registrationExtensionAuthenticatorInputs: AuthenticationExtensionsAuthenticatorInputs<RegistrationExtensionAuthenticatorInput>?
    private val options: AuthenticatorMakeCredentialRequest.Options?
    private val pinUvAuthParam: ByteArray?
    private val pinUvAuthProtocol: PinProtocolVersion?


    private val userCredentialBuilder: UserCredentialBuilder

    private val counter: Long = 0
    private var shouldCreateDiscoverableCredential = false
    private var shouldPerformUv = false
    private var shouldPerformUp = false

    //spec| Step 4. Create a new authenticatorMakeCredential response structure and initialize both its "uv" bit and "up" bit as false.
    private var uvResult = false
    private var upResult = false

    private lateinit var algorithmIdentifier: COSEAlgorithmIdentifier

    private lateinit var protocol: PinUvAuthProtocol
    // Step 11.2: result of performBuiltInUv(). When true (success), Step 13 sets UP from the UV
    // evidence and Step 14 (explicit UP test) is skipped.
    private var uvState = false
    private var uvNotRequired = false
    private var makeCredUvNotRqd = false
    private lateinit var userCredential: UserCredential

    private var registrationExtensionAuthenticatorOutputs: AuthenticationExtensionsAuthenticatorOutputs<RegistrationExtensionAuthenticatorOutput> = AuthenticationExtensionsAuthenticatorOutputs()

    private val isProtectedByUserVerification: Boolean
        get() = ctapAuthenticatorSession.isClientPINReady ||
                ctapAuthenticatorSession.userVerification == UserVerificationSetting.READY

    constructor(
        ctapAuthenticatorSession: CtapAuthenticatorSession,
        authenticatorMakeCredentialCommand: AuthenticatorMakeCredentialRequest
    ) : super(ctapAuthenticatorSession, authenticatorMakeCredentialCommand) {
        this.ctapAuthenticatorSession = ctapAuthenticatorSession
        this.authenticatorMakeCredentialRequest = authenticatorMakeCredentialCommand

        this.authenticatorPropertyStore = ctapAuthenticatorSession.authenticatorPropertyStore

        // command properties initialization and validation
        this.clientDataHash = authenticatorMakeCredentialCommand.clientDataHash
        this.rp = authenticatorMakeCredentialCommand.rp
        this.rpId = rp.id
        this.user = authenticatorMakeCredentialCommand.user
        this.pubKeyCredParams = authenticatorMakeCredentialCommand.pubKeyCredParams
        this.excludeList = authenticatorMakeCredentialCommand.excludeList
        this.registrationExtensionAuthenticatorInputs = authenticatorMakeCredentialCommand.extensions
        this.options = authenticatorMakeCredentialCommand.options
        this.pinUvAuthParam = authenticatorMakeCredentialCommand.pinUvAuthParam
        this.pinUvAuthProtocol = authenticatorMakeCredentialCommand.pinUvAuthProtocol
        // Default to the highest version protocol (list is sorted by version descending).
        // Overridden in Step 2 when pinUvAuthParam is present.
        this.protocol = ctapAuthenticatorSession.pinUvAuthManager.pinUvAuthProtocols.first()

        // user credential builder initialization
        this.userCredentialBuilder = UserCredentialBuilder(ctapAuthenticatorSession.objectConverter, authenticatorPropertyStore.loadEncryptionKey(), authenticatorPropertyStore.loadEncryptionIV())

        userCredentialBuilder.userHandle(user.id)
        userCredentialBuilder.username(user.name)
        userCredentialBuilder.displayName(user.displayName)
        userCredentialBuilder.rpId(rpId)
        userCredentialBuilder.rpName(rp.name)
        userCredentialBuilder.counter(counter)
        userCredentialBuilder.otherUI(null)
    }

    override suspend fun validate() {
        makeCredentialRequestValidator.validate(authenticatorMakeCredentialRequest)
    }

    override suspend fun doExecute(): AuthenticatorMakeCredentialResponse {
        ctapAuthenticatorSession.onGoingGetAssertionSession = null

        execStep1ZeroLengthPinUvAuthParam()
        execStep2ValidatePinUvAuthProtocol()
        execStep3ValidatePubKeyCredParams()
        // TODO: Step 4: Create a new response structure. Currently represented by field declarations (upResult=false, uvResult=false).
        execStep5ProcessOptions()
        // Initialize from authenticator setting; Step 6.1 may override to false when alwaysUv is enabled.
        makeCredUvNotRqd = ctapAuthenticatorSession.makeCredUvNotRqd == MakeCredUvNotRqdSetting.UV_NOT_REQUIRED
        execStep6ProcessAlwaysUv()
        execStep7And8ProcessMakeCredUvNotRqd()
        // TODO: Step 9: enterpriseAttestation processing
        execStep10CheckUvNotRequired()

        if (!uvNotRequired) {
            execStep11ProcessUserVerification()
        }

        execStep12ValidateExcludeList()
        execStep13SetUserPresenceFromBuiltInUv()
        if (!uvState) {
            execStep14TestUserPresence()
        }
        execStep15ProcessExtensions()
        execStep16to18CreateCredential()
        val response = execStep19GenerateAttestation()
        val event = MakeCredentialEvent(
            Instant.now(),
            rpId,
            rp.name,
            user.name,
            user.displayName,
            HashMap()
        )
        ctapAuthenticatorSession.publishEvent(event)
        return response
    }

    override fun createErrorResponse(statusCode: CtapStatusCode): AuthenticatorMakeCredentialResponse {
        return AuthenticatorMakeCredentialResponse(statusCode)
    }

    //spec| Step 1. If authenticator supports either pinUvAuthToken or clientPin features and the platform sends a
    //spec| zero length pinUvAuthParam:
    //spec|   1.1 Request evidence of user interaction in an authenticator-specific way (e.g., flash the LED light).
    //spec|   1.2 If the user declines permission, or the operation times out, then end the operation by returning CTAP2_ERR_OPERATION_DENIED.
    //spec|   1.3 If evidence of user interaction is provided in this step then return either
    //spec|   CTAP2_ERR_PIN_NOT_SET if PIN is not set or CTAP2_ERR_PIN_INVALID if PIN has been set.
    //
    // @see https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-makeCred-authnr-alg
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
    // @see https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-makeCred-authnr-alg
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

    //spec| Step 3. Validate pubKeyCredParams with the following steps:
    //spec|   3.1 For each element of pubKeyCredParams:
    //spec|     3.1.1 If the element is missing required members, including members that are mandatory only for the specific type, then return an error, for example CTAP2_ERR_INVALID_CBOR.
    //spec|     3.1.2 If the values of any known members have the wrong type then return an error, for example CTAP2_ERR_CBOR_UNEXPECTED_TYPE.
    //spec|     3.1.3 If the element specifies an algorithm that is supported by the authenticator, and no algorithm has yet been chosen by this loop, then let the algorithm specified by the current element be the chosen algorithm.
    //spec|   3.2 If the loop completes and no algorithm was chosen then return CTAP2_ERR_UNSUPPORTED_ALGORITHM.
    //
    // @see https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-makeCred-authnr-alg
    private fun execStep3ValidatePubKeyCredParams() {
        //spec| Step 3. Validate pubKeyCredParams with the following steps:
        //spec|   3.1 For each element of pubKeyCredParams:
        //spec|     3.1.1 If the element is missing required members, including members that are mandatory only for the specific type, then return an error, for example CTAP2_ERR_INVALID_CBOR.
        //spec|     3.1.2 If the values of any known members have the wrong type then return an error, for example CTAP2_ERR_CBOR_UNEXPECTED_TYPE.
        // TODO: 3.1.1 and 3.1.2 are currently handled by AuthenticatorMakeCredentialRequestValidator
        //  in the validate() step. Consider moving them here for better spec correspondence.
        //spec|     3.1.3 If the element specifies an algorithm that is supported by the authenticator, and no algorithm has yet been chosen by this loop, then let the algorithm specified by the current element be the chosen algorithm.
        //spec|   3.2 If the loop completes and no algorithm was chosen then return CTAP2_ERR_UNSUPPORTED_ALGORITHM.
        algorithmIdentifier =
            pubKeyCredParams.firstOrNull { it.type == PublicKeyCredentialType.PUBLIC_KEY && authenticatorPropertyStore.supports(it.alg) }?.alg
                ?: throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_UNSUPPORTED_ALGORITHM)
    }

    //spec| Step 5. If the options parameter is present, process all option keys and values present in the parameter. Treat any option keys that are not understood as absent.
    //spec|   5.1 If the "uv" option is absent, let the "uv" option be treated as being present with the value false. (This is the default)
    //spec|   5.2 If the pinUvAuthParam is present, let the "uv" option be treated as being present with the value false.
    //spec|   5.3 If the "uv" option is true then:
    //spec|     5.3.1 If the authenticator does not support a built-in user verification method end the operation by returning CTAP2_ERR_INVALID_OPTION.
    //spec|     5.3.2 If the built-in user verification method has not yet been enabled, end the operation by returning CTAP2_ERR_INVALID_OPTION.
    //spec|   5.4 If the "rk" option is present then:
    //spec|     5.4.1 If the rk option ID is not present in authenticatorGetInfo response, end the operation by returning CTAP2_ERR_UNSUPPORTED_OPTION.
    //spec|   5.5 Else: (the "rk" option is absent)
    //spec|     5.5.1 Let the "rk" option be treated as being present with the value false. (This is the default.)
    //spec|   5.6 If the "up" option is present then:
    //spec|     5.6.1 If the "up" option is false, end the operation by returning CTAP2_ERR_INVALID_OPTION.
    //spec|   5.7 If the "up" option is absent, let the "up" option be treated as being present with the value true (i.e., this is the default for both CTAP2.0 and CTAP2.1 authenticators).
    //
    // @see https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-makeCred-authnr-alg
    private fun execStep5ProcessOptions() {
        val requestOptions = options

        //spec| 5.1 If the "uv" option is absent, let the "uv" option be treated as being present with the value false. (This is the default)
        var uv = requestOptions?.uv ?: false
        //spec| 5.2 If the pinUvAuthParam is present, let the "uv" option be treated as being present with the value false.
        if (pinUvAuthParam != null) {
            uv = false
        }
        //spec| 5.3 If the "uv" option is true then:
        if (uv) {
            when (ctapAuthenticatorSession.userVerification) {
                //spec| 5.3.1 If the authenticator does not support a built-in user verification method end the operation by returning CTAP2_ERR_INVALID_OPTION.
                UserVerificationSetting.NOT_SUPPORTED -> throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_INVALID_OPTION)
                //spec| 5.3.2 If the built-in user verification method has not yet been enabled, end the operation by returning CTAP2_ERR_INVALID_OPTION.
                UserVerificationSetting.NOT_READY -> throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_INVALID_OPTION)
                UserVerificationSetting.READY -> {}
            }
        }
        shouldPerformUv = uv

        val rk: Boolean
        //spec| 5.4 If the "rk" option is present then:
        if (requestOptions?.rk != null) {
            //spec|   5.4.1 If the rk option ID is not present in authenticatorGetInfo response, end the operation by returning CTAP2_ERR_UNSUPPORTED_OPTION.
            // TODO: This duplicates GetInfoExecution's rk mapping. Consider refactoring to share the logic.
            val rkInGetInfo = when (ctapAuthenticatorSession.residentKey) {
                ResidentKeySetting.ALWAYS, ResidentKeySetting.IF_REQUIRED -> true
                ResidentKeySetting.NEVER -> false
            }
            if (!rkInGetInfo) {
                throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_UNSUPPORTED_OPTION)
            }
            rk = requestOptions.rk!!
        }
        //spec| 5.5 Else: (the "rk" option is absent)
        else {
            //spec|   5.5.1 Let the "rk" option be treated as being present with the value false. (This is the default.)
            rk = false
        }
        // Authenticator-specific policy: ALWAYS forces discoverable credential even when rk=false.
        // This is beyond the spec, which simply uses the rk value as-is after validation.
        shouldCreateDiscoverableCredential = rk || ctapAuthenticatorSession.residentKey == ResidentKeySetting.ALWAYS

        //spec| 5.6 If the "up" option is present then:
        //spec|   5.6.1 If the "up" option is false, end the operation by returning CTAP2_ERR_INVALID_OPTION.
        if (requestOptions?.up == false) {
            throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_INVALID_OPTION)
        }
        //spec| 5.7 If the "up" option is absent, let the "up" option be treated as being present with the value true
        //spec| (i.e., this is the default for both CTAP2.0 and CTAP2.1 authenticators).
        shouldPerformUp = when (ctapAuthenticatorSession.userPresence) {
            UserPresenceSetting.SUPPORTED -> true
            else -> throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_INVALID_OPTION)
        }
    }

    //spec| Step 6. If the alwaysUv option ID is present and true then:
    //spec|   6.1 Let the makeCredUvNotRqd option ID be treated as false.
    //spec|   6.2 If the authenticator is not protected by some form of user verification:
    //spec|     6.2.1 If the clientPin option ID is present and noMcGaPermissionsWithClientPin option ID is absent or false (clientPin is supported for the mc permission):
    //spec|       6.2.1.1 End the operation by returning CTAP2_ERR_PUAT_REQUIRED.
    //spec|     6.2.2 Else (clientPin is not supported):
    //spec|       6.2.2.1 End the operation by returning CTAP2_ERR_OPERATION_DENIED.
    //spec|   6.3 If the pinUvAuthParam is not present, and the uv option ID is true, let the "uv" option be treated as being present with the value true.
    //spec|   6.4 If the pinUvAuthParam is not present, and the "uv" option is false or absent:
    //spec|     6.4.1 If the clientPin option ID is present and noMcGaPermissionsWithClientPin option ID is absent or false (clientPin is supported for the mc permission):
    //spec|       6.4.1.1 End the operation by returning CTAP2_ERR_PUAT_REQUIRED.
    //spec|     6.4.2 Else (clientPin is not supported):
    //spec|       6.4.2.1 End the operation by returning CTAP2_ERR_OPERATION_DENIED.
    //
    // @see https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-makeCred-authnr-alg
    private fun execStep6ProcessAlwaysUv() {
        //spec| Step 6. If the alwaysUv option ID is present and true then:
        if (ctapAuthenticatorSession.alwaysUv == AlwaysUvSetting.ENABLED) {
            //spec| 6.1 Let the makeCredUvNotRqd option ID be treated as false.
            makeCredUvNotRqd = false

            //spec| 6.2 If the authenticator is not protected by some form of user verification:
            if (!isProtectedByUserVerification) {
                //spec| 6.2.1 If the clientPin option ID is present and noMcGaPermissionsWithClientPin option ID is absent or false (clientPin is supported for the mc permission):
                // TODO: noMcGaPermissionsWithClientPin not yet implemented; always treated as absent
                if (ctapAuthenticatorSession.clientPIN == ClientPINSetting.ENABLED) {
                    //spec| 6.2.1.1 End the operation by returning CTAP2_ERR_PUAT_REQUIRED.
                    throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_PUAT_REQUIRED)
                }
                //spec| 6.2.2 Else (clientPin is not supported):
                else {
                    //spec|   6.2.2.1 End the operation by returning CTAP2_ERR_OPERATION_DENIED.
                    throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_OPERATION_DENIED)
                }
            }

            //spec| 6.3 If the pinUvAuthParam is not present, and the uv option ID is true, let the "uv" option be treated as being present with the value true.
            // No-op: Step 5.3 already set shouldPerformUv=true when uv=true, and Step 6 never
            // resets it. This spec step exists to explicitly confirm that alwaysUv processing does not
            // override an explicit uv=true from a CTAP2.0 platform unaware of the alwaysUv feature.

            //spec| 6.4 If the pinUvAuthParam is not present, and the "uv" option is false or absent:
            if (pinUvAuthParam == null && !shouldPerformUv) {
                //spec| 6.4.1 If the clientPin option ID is present and noMcGaPermissionsWithClientPin option ID is absent or false (clientPin is supported for the mc permission):
                // TODO: noMcGaPermissionsWithClientPin not yet implemented; always treated as absent
                if (ctapAuthenticatorSession.clientPIN == ClientPINSetting.ENABLED) {
                    //spec| 6.4.1.1 End the operation by returning CTAP2_ERR_PUAT_REQUIRED.
                    throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_PUAT_REQUIRED)
                } else {
                    //spec| 6.4.2 Else (clientPin is not supported):
                    //spec|   6.4.2.1 End the operation by returning CTAP2_ERR_OPERATION_DENIED.
                    throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_OPERATION_DENIED)
                }
            }
        }
    }

    //spec| Step 7. If the makeCredUvNotRqd option ID is present and set to true in the authenticatorGetInfo response:
    //spec|   7.1 If the following statements are all true:
    //spec|     7.1.1 The authenticator is protected by some form of user verification.
    //spec|     7.1.2 The "uv" option is set to false.
    //spec|     7.1.3 The pinUvAuthParam parameter is not present.
    //spec|     7.1.4 The "rk" option is present and set to true.
    //spec|   Then:
    //spec|     7.1.1 If ClientPin option ID is true and the noMcGaPermissionsWithClientPin option ID is absent or false,
    //spec|     end the operation by returning CTAP2_ERR_PUAT_REQUIRED.
    //spec|     7.1.2 Otherwise, end the operation by returning CTAP2_ERR_OPERATION_DENIED.
    //spec| Step 8. Else: (the makeCredUvNotRqd option ID in authenticatorGetInfo's response is present with the value false or is absent):
    //spec|   8.1 If the following statements are all true:
    //spec|     8.1.1 The authenticator is protected by some form of user verification.
    //spec|     8.1.2 The "uv" option is set to false.
    //spec|     8.1.3 The pinUvAuthParam parameter is not present.
    //spec|   Then:
    //spec|     8.1.1 If the ClientPin option ID is true and the noMcGaPermissionsWithClientPin option ID is absent or false,
    //spec|     end the operation by returning CTAP2_ERR_PUAT_REQUIRED.
    //spec|     8.1.2 Otherwise, end the operation by returning CTAP2_ERR_OPERATION_DENIED.
    //
    // @see https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-makeCred-authnr-alg
    private fun execStep7And8ProcessMakeCredUvNotRqd() {
        //spec| Step 7. If the makeCredUvNotRqd option ID is present and set to true in the authenticatorGetInfo response:
        if (makeCredUvNotRqd) {
            //spec| 7.1 If the following statements are all true:
            //spec|   7.1.1 The authenticator is protected by some form of user verification.
            //spec|   7.1.2 The "uv" option is set to false.
            //spec|   7.1.3 The pinUvAuthParam parameter is not present.
            //spec|   7.1.4 The "rk" option is present and set to true.
            if (isProtectedByUserVerification && !shouldPerformUv && pinUvAuthParam == null && options?.rk == true) {
                //spec| Then:
                //spec|   7.1.1 If ClientPin option ID is true and the noMcGaPermissionsWithClientPin option ID is absent or false,
                //spec|   end the operation by returning CTAP2_ERR_PUAT_REQUIRED.
                // TODO: noMcGaPermissionsWithClientPin not yet implemented; always treated as absent
                if (ctapAuthenticatorSession.isClientPINReady) {
                    throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_PUAT_REQUIRED)
                } else {
                    //spec|   7.1.2 Otherwise, end the operation by returning CTAP2_ERR_OPERATION_DENIED.
                    throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_OPERATION_DENIED)
                }
            }
        } else {
            //spec| Step 8. Else: (the makeCredUvNotRqd option ID in authenticatorGetInfo's response is present with the value false or is absent):
            //spec| 8.1 If the following statements are all true:
            //spec|   8.1.1 The authenticator is protected by some form of user verification.
            //spec|   8.1.2 The "uv" option is set to false.
            //spec|   8.1.3 The pinUvAuthParam parameter is not present.
            if (isProtectedByUserVerification && !shouldPerformUv && pinUvAuthParam == null) {
                //spec| Then:
                //spec|   8.1.1 If the ClientPin option ID is true and the noMcGaPermissionsWithClientPin option ID is absent or false,
                // TODO: noMcGaPermissionsWithClientPin not yet implemented; always treated as absent
                if (ctapAuthenticatorSession.isClientPINReady) {
                    //spec|   end the operation by returning CTAP2_ERR_PUAT_REQUIRED.
                    throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_PUAT_REQUIRED)
                } else {
                    //spec|   8.1.2 Otherwise, end the operation by returning CTAP2_ERR_OPERATION_DENIED.
                    throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_OPERATION_DENIED)
                }
            }
        }
    }

    //spec| Step 10. If the following statements are all true:
    //spec|   10.1 "rk" and "uv" options are both set to false or omitted.
    //spec|   10.2 the makeCredUvNotRqd option ID in authenticatorGetInfo's response is present with the value true.
    //spec|   10.3 the pinUvAuthParam parameter is not present.
    //spec| Then go to Step 12.
    //
    // @see https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-makeCred-authnr-alg
    private fun execStep10CheckUvNotRequired() {
        //spec| Step 10. If the following statements are all true:
        val uvNotRequiredConditions =
            //spec| 10.1 "rk" and "uv" options are both set to false or omitted.
            options?.rk != true && !shouldPerformUv &&
            //spec| 10.2 the makeCredUvNotRqd option ID in authenticatorGetInfo's response is present with the value true.
            makeCredUvNotRqd &&
            //spec| 10.3 the pinUvAuthParam parameter is not present.
            pinUvAuthParam == null
        //spec| Then go to Step 12.
        if (uvNotRequiredConditions) {
            uvNotRequired = true
        }
    }

    //spec| Step 11. If the authenticator is protected by some form of user verification, then:
    //spec|   11.1 If pinUvAuthParam parameter is present (implying the "uv" option is false (see Step 5)):
    //spec|     11.1.1 Call verify(pinUvAuthToken, clientDataHash, pinUvAuthParam).
    //spec|     If the verification returns error, then end the operation by returning CTAP2_ERR_PIN_AUTH_INVALID error.
    //spec|     11.1.2 Verify that the pinUvAuthToken has the mc permission, if not, then end the operation by returning CTAP2_ERR_PIN_AUTH_INVALID.
    //spec|     11.1.3 If the pinUvAuthToken has a permissions RP ID associated:
    //spec|       If the permissions RP ID does not match the rp.id in this request, then end the operation by returning CTAP2_ERR_PIN_AUTH_INVALID.
    //spec|     11.1.4 Let userVerifiedFlagValue be the result of calling getUserVerifiedFlagValue().
    //spec|     11.1.5 If userVerifiedFlagValue is false then end the operation by returning CTAP2_ERR_PIN_AUTH_INVALID.
    //spec|     11.1.6 If userVerifiedFlagValue is true then set the "uv" bit to true in the response.
    //spec|     11.1.7 If the pinUvAuthToken does not have a permissions RP ID associated:
    //spec|       Associate the request's rp.id parameter value with the pinUvAuthToken as its permissions RP ID.
    //spec|     11.1.8 Go to Step 12.
    //spec|   11.2 If the "uv" option is present and set to true (implying the pinUvAuthParam parameter is not present,
    //spec|   and that the authenticator supports an enabled built-in user verification method, see Step 5):
    //spec|     11.2.1 Let internalRetry be true.
    //spec|     11.2.2 Let uvState be the result of calling performBuiltInUv(internalRetry)
    //spec|     11.2.3 If uvState is error:
    //spec|       11.2.3.1 If the error reason is a user action timeout, then return CTAP2_ERR_USER_ACTION_TIMEOUT.
    //spec|       11.2.3.2 If the uvRetries counter is 0, return CTAP2_ERR_PIN_BLOCKED.
    //spec|       11.2.3.3 Otherwise, end the operation by returning CTAP2_ERR_OPERATION_DENIED.
    //spec|     11.2.4 If uvState is success:
    //spec|       11.2.4.1 Set the "uv" bit to true in the response.
    //
    // @see https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-makeCred-authnr-alg
    private suspend fun execStep11ProcessUserVerification() {
        //spec| Step 11. If the authenticator is protected by some form of user verification, then:
        if (isProtectedByUserVerification) {
            //spec| 11.1 If pinUvAuthParam parameter is present (implying the "uv" option is false (see Step 5)):
            if (pinUvAuthParam != null) {
                //spec| 11.1.1 Call verify(pinUvAuthToken, clientDataHash, pinUvAuthParam).
                //spec| If the verification returns error, then end the operation by returning CTAP2_ERR_PIN_AUTH_INVALID error.
                if (!protocol.verify(protocol.pinUvAuthToken, clientDataHash, pinUvAuthParam)) {
                    throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_PIN_AUTH_INVALID)
                }

                //spec| 11.1.2 Verify that the pinUvAuthToken has the mc permission, if not, then end the operation by returning CTAP2_ERR_PIN_AUTH_INVALID.
                if (!protocol.tokenState.hasPermission(PinUvAuthTokenPermission.MC)) {
                    throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_PIN_AUTH_INVALID)
                }

                //spec| 11.1.3 If the pinUvAuthToken has a permissions RP ID associated:
                //spec|   If the permissions RP ID does not match the rp.id in this request, then end the operation by returning CTAP2_ERR_PIN_AUTH_INVALID.
                val tokenRpId = protocol.tokenState.permissionsRpId
                if (tokenRpId != null && tokenRpId != rpId) {
                    throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_PIN_AUTH_INVALID)
                }

                //spec| 11.1.4 Let userVerifiedFlagValue be the result of calling getUserVerifiedFlagValue().
                val userVerifiedFlagValue = protocol.tokenState.getUserVerifiedFlagValue()
                if (!userVerifiedFlagValue) {
                    //spec| 11.1.5 If userVerifiedFlagValue is false then end the operation by returning CTAP2_ERR_PIN_AUTH_INVALID.
                    throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_PIN_AUTH_INVALID)
                }
                else{
                    //spec| 11.1.6 If userVerifiedFlagValue is true then set the "uv" bit to true in the response.
                    uvResult = true
                }

                //spec| 11.1.7 If the pinUvAuthToken does not have a permissions RP ID associated:
                //spec|   Associate the request's rp.id parameter value with the pinUvAuthToken as its permissions RP ID.
                if (protocol.tokenState.permissionsRpId == null) {
                    protocol.tokenState.permissionsRpId = rpId
                }

                // Record token usage to prevent expiration by initial usage time limit (§6.5.2.1)
                protocol.tokenState.recordTokenUsage()
                //spec| 11.1.8 Go to Step 12.
                return
            }

            //spec| 11.2 If the "uv" option is present and set to true (implying the pinUvAuthParam parameter is not present,
            //spec| and that the authenticator supports an enabled built-in user verification method, see Step 5):
            if (shouldPerformUv) {
                //spec| 11.2.1 Let internalRetry be true.
                //spec| 11.2.2 Let uvState be the result of calling performBuiltInUv(internalRetry)
                uvState = performBuiltInUv()
                if (!uvState) {
                    //spec| 11.2.3 If uvState is error:
                    //spec|   11.2.3.1 If the error reason is a user action timeout, then return CTAP2_ERR_USER_ACTION_TIMEOUT.
                    //spec|   11.2.3.2 If the uvRetries counter is 0, return CTAP2_ERR_PIN_BLOCKED.
                    //spec|   11.2.3.3 Otherwise, end the operation by returning CTAP2_ERR_OPERATION_DENIED.
                    // Simplified: performBuiltInUv() returns a boolean; detailed error reasons
                    // (timeout, blocked) are not yet distinguished.
                    throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_OPERATION_DENIED)
                }
                else{
                    //spec| 11.2.4 If uvState is success:
                    //spec|   11.2.4.1 Set the "uv" bit to true in the response.
                    uvResult = true
                }
            }
        }
    }

    //spec| Step 12. If the excludeList parameter is present and contains a credential ID created by this authenticator,
    //spec| that is bound to the specified rp.id:
    //spec|   12.1 If the credential's credProtect value is not userVerificationRequired, then:
    //spec|     12.1.4 If userPresentFlagValue is false, then:
    //spec|       12.1.4.1 Wait for user presence.
    //spec|       12.1.4.2 Regardless of whether user presence is obtained or the authenticator times out,
    //spec|       terminate this procedure and return CTAP2_ERR_CREDENTIAL_EXCLUDED.
    //spec|     12.1.5 Else, (implying userPresentFlagValue is true) terminate this procedure
    //spec|     and return CTAP2_ERR_CREDENTIAL_EXCLUDED.
    //spec|   12.2 Else (implying the credential's credProtect value is userVerificationRequired):
    // 12.1 vs 12.2 distinction is delegated to MakeCredentialCredentialFilter implementations (e.g., CredProtectExtensionProcessor).
    //
    // @see https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-makeCred-authnr-alg
    private suspend fun execStep12ValidateExcludeList() {
        //spec| Step 12. If the excludeList parameter is present and contains a credential ID created by this authenticator,
        //spec| that is bound to the specified rp.id:
        excludeList.let {
            if (it != null && it.isNotEmpty()) {
                val rpId = rp.id
                val userCredentials = authenticatorPropertyStore.loadUserCredentials(rpId)
                val credentialFilters = ctapAuthenticatorSession.extensionProcessors
                    .filterIsInstance<MakeCredentialCredentialFilter>()
                val residentMatch = userCredentials.any { credentialSource ->
                    //spec| 12.1 If the credential's credProtect value is not userVerificationRequired, then:
                    //spec| 12.2 Else (implying the credential's credProtect value is userVerificationRequired):
                    // Filtering is delegated to MakeCredentialCredentialFilter; false = 12.2 (skip), true = 12.1 (proceed).
                    credentialFilters.all { it.test(MakeCredentialCredentialFilterContext(authenticatorMakeCredentialRequest, credentialSource, uvResult)) } &&
                    it.any { descriptor ->
                        Arrays.equals(descriptor.id, credentialSource.credentialId)
                    }
                }
                val nonResidentMatch = !residentMatch && it.any { descriptor ->
                    isKnownCredentialId(descriptor, rpId)
                }
                if (residentMatch || nonResidentMatch) {
                    //spec| 12.1.4 If userPresentFlagValue is false, then:
                    //spec|   12.1.4.1 Wait for user presence.
                    val makeCredentialConsentRequest = MakeCredentialConsentRequest(
                        rp,
                        user,
                        isUserPresence = true,
                        isUserVerification = false
                    )
                    ctapAuthenticatorSession.withUserPresenceWait {
                        ctapAuthenticatorSession.makeCredentialConsentHandler.onMakeCredentialConsentRequested(
                            makeCredentialConsentRequest
                        )
                    }
                    //spec|   12.1.4.2 Regardless of whether user presence is obtained or the authenticator times out,
                    //spec|   terminate this procedure and return CTAP2_ERR_CREDENTIAL_EXCLUDED.
                    //spec| 12.1.5 Else, (implying userPresentFlagValue is true) terminate this procedure
                    //spec| and return CTAP2_ERR_CREDENTIAL_EXCLUDED.
                    throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_CREDENTIAL_EXCLUDED)
                }
            }
        }
    }

    private fun isKnownCredentialId(descriptor: PublicKeyCredentialDescriptor, rpId: String): Boolean {
        try {
            val decrypted = CipherUtil.decryptWithAESCBCPKCS5Padding(
                descriptor.id,
                authenticatorPropertyStore.loadEncryptionKey(),
                authenticatorPropertyStore.loadEncryptionIV()
            ) ?: return false
            val source = ctapAuthenticatorSession.objectConverter.cborMapper.readValue(
                decrypted,
                NonResidentUserCredentialSource::class.java
            ) ?: return false
            return source.rpId == rpId
        } catch (e: RuntimeException) {
            return false
        }
    }

    //spec| Step 13. If evidence of user interaction was provided as part of Step 11 (i.e., by invoking performBuiltInUv()):
    //spec|   13.1 Set the "up" bit to true in the response.
    //spec|   13.2 Go to Step 15
    //
    // @see https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-makeCred-authnr-alg
    private fun execStep13SetUserPresenceFromBuiltInUv() {
        //spec| Step 13. If evidence of user interaction was provided as part of Step 11 (i.e., by invoking performBuiltInUv()):
        if (uvState) {
            //spec| 13.1 Set the "up" bit to true in the response.
            upResult = true
            //spec| 13.2 Go to Step 15
        }
    }

    //spec| Step 14. If the "up" option is set to true:
    //spec|   14.1 If the pinUvAuthParam parameter is present then:
    //spec|     14.1.1 Let userPresentFlagValue be the result of calling getUserPresentFlagValue().
    //spec|     14.1.2 If userPresentFlagValue is false:
    //spec|       14.1.2.1 Request evidence of user interaction in an authenticator-specific way (e.g., flash the LED light).
    //spec|       If the authenticator has a display, show the items contained within the user and rp parameter structures to the user,
    //spec|       and request permission to create a credential.
    //spec|       14.1.2.2 If the user declines permission, or the operation times out, then end the operation by returning CTAP2_ERR_OPERATION_DENIED.
    //spec|   14.2 Else (implying the pinUvAuthParam parameter is not present):
    //spec|     14.2.1 If the "up" bit is false in the response:
    //spec|       14.2.1.1 Request evidence of user interaction in an authenticator-specific way (e.g., flash the LED light).
    //spec|       If the authenticator has a display, show the items contained within the user and rp parameter structures to the user,
    //spec|       and request permission to create a credential.
    //spec|       14.2.1.2 If the user declines permission, or the operation times out, then end the operation by returning CTAP2_ERR_OPERATION_DENIED.
    //spec|   14.3 Set the "up" bit to true in the response.
    //spec|   14.4 Call clearUserPresentFlag(), clearUserVerifiedFlag(), and clearPinUvAuthTokenPermissionsExceptLbw().
    //
    // @see https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-makeCred-authnr-alg
    private suspend fun execStep14TestUserPresence() {
        //spec| Step 14. If the "up" option is set to true:
        if (shouldPerformUp) {
            //spec| 14.1 If the pinUvAuthParam parameter is present then:
            if (pinUvAuthParam != null) {
                //spec| 14.1.1 Let userPresentFlagValue be the result of calling getUserPresentFlagValue().
                val userPresentFlagValue = protocol.tokenState.getUserPresentFlagValue()
                //spec| 14.1.2 If userPresentFlagValue is false:
                if (!userPresentFlagValue) {
                    //spec| 14.1.2.1 Request evidence of user interaction in an authenticator-specific way (e.g., flash the LED light).
                    //spec| If the authenticator has a display, show the items contained within the user and rp parameter structures to the user,
                    //spec| and request permission to create a credential.
                    //spec| 14.1.2.2 If the user declines permission, or the operation times out, then end the operation by returning CTAP2_ERR_OPERATION_DENIED.
                    if (!performBuiltInUp()) {
                        throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_OPERATION_DENIED)
                    }
                }
            } else {
                //spec| 14.2 Else (implying the pinUvAuthParam parameter is not present):
                //spec|   14.2.1 If the "up" bit is false in the response:
                if (!upResult) {
                    //spec| 14.2.1.1 Request evidence of user interaction in an authenticator-specific way (e.g., flash the LED light).
                    //spec| If the authenticator has a display, show the items contained within the user and rp parameter structures to the user,
                    //spec| and request permission to create a credential.
                    //spec| 14.2.1.2 If the user declines permission, or the operation times out, then end the operation by returning CTAP2_ERR_OPERATION_DENIED.
                    if (!performBuiltInUp()) {
                        throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_OPERATION_DENIED)
                    }
                }
            }

            //spec| 14.3 Set the "up" bit to true in the response.
            upResult = true

            //spec| 14.4 Call clearUserPresentFlag(), clearUserVerifiedFlag(), and clearPinUvAuthTokenPermissionsExceptLbw().
            protocol.tokenState.clearUserPresentFlag()
            protocol.tokenState.clearUserVerifiedFlag()
            protocol.tokenState.clearPinUvAuthTokenPermissionsExceptLbw()
        }
    }

    private suspend fun performBuiltInUv(): Boolean {
        val makeCredentialConsentRequest = MakeCredentialConsentRequest(
            rp,
            user,
            isUserPresence = true,
            isUserVerification = true
        )
        return ctapAuthenticatorSession.withUserPresenceWait {
            ctapAuthenticatorSession.makeCredentialConsentHandler.onMakeCredentialConsentRequested(makeCredentialConsentRequest)
        }
    }

    private suspend fun performBuiltInUp(): Boolean {
        val makeCredentialConsentRequest = MakeCredentialConsentRequest(
            rp,
            user,
            isUserPresence = true,
            isUserVerification = false
        )
        return ctapAuthenticatorSession.withUserPresenceWait {
            ctapAuthenticatorSession.makeCredentialConsentHandler.onMakeCredentialConsentRequested(makeCredentialConsentRequest)
        }
    }

    //spec| Step 15. If the extensions parameter is present:
    //spec|   15.1 Process any extensions that this authenticator supports, ignoring any that it does not support.
    //spec|   15.2 Authenticator extension outputs generated by the authenticator extension processing
    //spec|   are returned in the authenticator data.
    //spec|   15.3 The set of keys in the authenticator extension outputs map MUST be equal to, or a subset of, the keys of the authenticator extension inputs map.
    //
    // @see https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-makeCred-authnr-alg
    private fun execStep15ProcessExtensions() {
        //spec| Step 15. If the extensions parameter is present:
        val inputs = this.registrationExtensionAuthenticatorInputs
        if (inputs != null) {
            //spec| 15.1 Process any extensions that this authenticator supports, ignoring any that it does not support.
            val outputsBuilder = AuthenticationExtensionsAuthenticatorOutputs.BuilderForRegistration()
            ctapAuthenticatorSession.extensionProcessors.filterIsInstance<RegistrationExtensionProcessor>().forEach { processor ->
                if (processor.supportsRegistrationExtension(inputs)) {
                    val context = RegistrationExtensionContext(ctapAuthenticatorSession, authenticatorMakeCredentialRequest)
                    processor.processRegistrationExtension(context, userCredentialBuilder, outputsBuilder)
                }
            }
            //spec| 15.2 Authenticator extension outputs generated by the authenticator extension processing
            //spec| are returned in the authenticator data.
            registrationExtensionAuthenticatorOutputs = outputsBuilder.build()
        }
    }

    //spec| Step 16. Generate a new credential key pair for the algorithm chosen in step 3.
    //spec| Step 17. If the "rk" option is set to true:
    //spec|   17.1 The authenticator MUST create a discoverable credential.
    //spec|   17.2 If a credential for the same rp.id and account ID already exists on the authenticator:
    //spec|     17.2.1 If the existing credential contains a largeBlobKey, an authenticator MAY erase any associated large-blob data.
    //spec|     17.2.2 Overwrite that credential.
    //spec|   17.3 Store the user parameter along with the newly-created key pair.
    //spec|   17.4 If authenticator does not have enough internal storage to persist the new credential, return CTAP2_ERR_KEY_STORE_FULL.
    //spec|   17.5 Generate a new 128-bit random value for credential store state.
    //spec| Step 18. Otherwise, if the "rk" option is false: the authenticator MUST create a non-discoverable credential.
    //
    // @see https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-makeCred-authnr-alg
    private fun execStep16to18CreateCredential() {
        //spec| Step 16. Generate a new credential key pair for the algorithm chosen in step 3.
        //spec| Step 17. If the "rk" option is set to true:
        if (shouldCreateDiscoverableCredential) {
            //spec|   17.1 The authenticator MUST create a discoverable credential.
            val credentialId = ByteArray(32)
            secureRandom.nextBytes(credentialId)
            userCredentialBuilder.credentialId(credentialId)

            val credentialKey: CredentialKey
            try {
                credentialKey = authenticatorPropertyStore.createUserCredentialKey(algorithmIdentifier, clientDataHash)
            } catch (e: StoreFullException) {
                throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_KEY_STORE_FULL, e)
            }
            userCredentialBuilder.userCredentialKey(credentialKey)
            userCredentialBuilder.createdAt(Instant.now())
            userCredential = userCredentialBuilder.build()

            //spec|   17.2 If a credential for the same rp.id and account ID already exists on the authenticator:
            //spec|     17.2.1 If the existing credential contains a largeBlobKey, an authenticator MAY erase any associated large-blob data.
            // TODO: largeBlobKey not yet implemented
            //spec|     17.2.2 Overwrite that credential.
            removeExistingCredentialForSameAccount(userCredential as ResidentUserCredential)
            try {
                //spec|   17.3 Store the user parameter along with the newly-created key pair.
                authenticatorPropertyStore.saveUserCredential(userCredential as ResidentUserCredential)
            } catch (e: StoreFullException) {
                //spec|   17.4 If authenticator does not have enough internal storage to persist the new credential, return CTAP2_ERR_KEY_STORE_FULL.
                throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_KEY_STORE_FULL)
            }
            //spec|   17.5 Generate a new 128-bit random value for credential store state.
            // TODO: credential store state not yet implemented
        } else {
            //spec| Step 18. Otherwise, if the "rk" option is false: the authenticator MUST create a non-discoverable credential.
            val credentialKey = NonResidentCredentialKey.create(
                algorithmIdentifier,
                createCredentialKeyPair(algorithmIdentifier)
            )
            userCredentialBuilder.userCredentialKey(credentialKey)
            userCredentialBuilder.createdAt(Instant.now())
            userCredential = userCredentialBuilder.build()
        }
    }

    //spec| Step 19. If the authenticator doesn't support multiple attestation formats or the attestationFormatsPreference is absent or its value is the empty list,
    //spec|   generate an attestation statement for the newly-created credential using
    //spec|   clientDataHash, taking into account the value of the enterpriseAttestation parameter, if present, as described above in Step 9.
    //
    // @see https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-makeCred-authnr-alg
    private suspend fun execStep19GenerateAttestation(): AuthenticatorMakeCredentialResponse {
        //spec| Step 19. If the authenticator doesn't support multiple attestation formats or the attestationFormatsPreference is absent or its value is the empty list,
        //spec|   generate an attestation statement for the newly-created credential using
        //spec|   clientDataHash, taking into account the value of the enterpriseAttestation parameter, if present, as described above in Step 9.
        val rpIdHash = MessageDigestUtil.createSHA256().digest(rpId.toByteArray())
        val alg = COSEAlgorithmIdentifier.create(userCredential.credentialKey.alg!!)
        val authenticatorDataProvider: AttestationStatementRequest.AuthenticatorDataProvider =
            object : AttestationStatementRequest.AuthenticatorDataProvider {
                override fun provide(
                    credentialId: ByteArray,
                    credentialPublicKey: COSEKey
                ): AuthenticatorData<RegistrationExtensionAuthenticatorOutput> {
                    return createAuthenticatorData(credentialId, credentialPublicKey)
                }
            }
        val attestationStatementRequest = AttestationStatementRequest(
            rpIdHash,
            alg,
            userCredential.credentialId,
            authenticatorMakeCredentialRequest.clientDataHash,
            shouldCreateDiscoverableCredential,
            userCredential.credentialKey,
            authenticatorDataProvider
        )
        val attestationStatement: AttestationStatement =
            ctapAuthenticatorSession.attestationStatementProvider.provide(attestationStatementRequest)

        try {
            val responseData = AuthenticatorMakeCredentialResponseData(
                attestationStatementRequest.authenticatorData,
                attestationStatement
            )
            return AuthenticatorMakeCredentialResponse(CtapStatusCode.CTAP2_OK, responseData)
        } catch (e: java.lang.RuntimeException) {
            if (userCredential is ResidentUserCredential) {
                removeIncompleteUserCredential(userCredential as ResidentUserCredential)
            }
            throw e
        }
    }

    private fun removeExistingCredentialForSameAccount(newCredential: ResidentUserCredential) {
        val existingCredentials = authenticatorPropertyStore.loadUserCredentials(newCredential.rpId)
        existingCredentials
            .filter { Arrays.equals(it.userHandle, newCredential.userHandle) }
            .forEach { authenticatorPropertyStore.removeUserCredential(it.credentialId) }
    }

    private fun removeIncompleteUserCredential(userCredential: ResidentUserCredential?) {
        if (userCredential != null) {
            try {
                authenticatorPropertyStore.removeUserCredential(userCredential.credentialId)
            } catch (e: RuntimeException) {
                logger.error("Failed to remove in complete credential.", e)
            }
        }
    }

    private fun createAuthenticatorData(
        credentialId: ByteArray,
        credentialPublicKey: COSEKey
    ): AuthenticatorData<RegistrationExtensionAuthenticatorOutput> {
        val rpIdHash =
            MessageDigestUtil.createSHA256().digest(rpId.toByteArray(StandardCharsets.UTF_8))
        var flag = AuthenticatorData.BIT_AT
        if (upResult) flag = flag or AuthenticatorData.BIT_UP
        if (uvResult) flag = flag or AuthenticatorData.BIT_UV
        if (registrationExtensionAuthenticatorOutputs.keys.isNotEmpty()) flag =
            flag or AuthenticatorData.BIT_ED
        val attestedCredentialData =
            AttestedCredentialData(ctapAuthenticatorSession.aaguid, credentialId, credentialPublicKey)
        return AuthenticatorData(
            rpIdHash,
            flag,
            counter,
            attestedCredentialData,
            registrationExtensionAuthenticatorOutputs
        )
    }

}
