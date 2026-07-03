package com.webauthn4j.ctap.authenticator.execution


import tools.jackson.dataformat.cbor.CBORMapper
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
    private val cborMapper: CBORMapper
    private val secureRandom = SecureRandom()

    // command properties
    private val clientDataHash: ByteArray
    private val rp: CtapPublicKeyCredentialRpEntity
    private val rpId: String?
    private val user: CtapPublicKeyCredentialUserEntity
    private val pubKeyCredParams: List<PublicKeyCredentialParameters>
    private val excludeList: List<PublicKeyCredentialDescriptor>?
    private val registrationExtensionAuthenticatorInputs: AuthenticationExtensionsAuthenticatorInputs<RegistrationExtensionAuthenticatorInput>?
    private val options: AuthenticatorMakeCredentialRequest.Options?
    private val pinAuth: ByteArray?
    private val pinProtocol: PinProtocolVersion?


    private val userCredentialBuilder: UserCredentialBuilder

    private val counter: Long = 0
    private var residentKeyPlan = false
    private var userVerificationPlan = false
    private var userPresencePlan = false

    //spec| Step 4. Create a new authenticatorMakeCredential response structure and initialize both its "uv" bit and "up" bit as false.
    private var userVerificationResult = false
    private var userPresenceResult = false

    private lateinit var algorithmIdentifier: COSEAlgorithmIdentifier

    private var matchedProtocol: PinUvAuthProtocol? = null
    private var uvPerformedViaBuiltIn = false
    private var uvNotRequired = false

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
        this.cborMapper = ctapAuthenticatorSession.objectConverter.cborMapper

        // command properties initialization and validation
        this.clientDataHash = authenticatorMakeCredentialCommand.clientDataHash
        this.rp = authenticatorMakeCredentialCommand.rp
        this.rpId = rp.id
        this.user = authenticatorMakeCredentialCommand.user
        this.pubKeyCredParams = authenticatorMakeCredentialCommand.pubKeyCredParams
        this.excludeList = authenticatorMakeCredentialCommand.excludeList
        this.registrationExtensionAuthenticatorInputs = authenticatorMakeCredentialCommand.extensions
        this.options = authenticatorMakeCredentialCommand.options
        this.pinAuth = authenticatorMakeCredentialCommand.pinAuth
        this.pinProtocol = authenticatorMakeCredentialCommand.pinProtocol

        // user credential builder initialization
        this.userCredentialBuilder = UserCredentialBuilder(ctapAuthenticatorSession.objectConverter, authenticatorPropertyStore.loadEncryptionKey(), authenticatorPropertyStore.loadEncryptionIV())

        userCredentialBuilder.userHandle(user.id)
        userCredentialBuilder.username(user.name)
        userCredentialBuilder.displayName(user.displayName)
        userCredentialBuilder.icon(user.icon)
        userCredentialBuilder.rpId(rpId)
        userCredentialBuilder.rpName(rp.name)
        userCredentialBuilder.rpIcon(rp.icon)
        userCredentialBuilder.counter(counter)
        userCredentialBuilder.otherUI(null)
    }

    override suspend fun validate() {
        makeCredentialRequestValidator.validate(authenticatorMakeCredentialRequest)
    }

    override suspend fun doExecute(): AuthenticatorMakeCredentialResponse {
        if (rpId == null) {
            throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_MISSING_PARAMETER)
        }
        ctapAuthenticatorSession.onGoingGetAssertionSession = null

        execStep1ZeroLengthPinUvAuthParam()
        execStep2ValidatePinUvAuthProtocol()
        execStep3ValidatePubKeyCredParams()
        // Step 4: response structure initialized via field declarations (userPresenceResult=false, userVerificationResult=false)
        execStep5ProcessOptions()
        execStep6ProcessAlwaysUv()
        execStep7ProcessMakeCredUvNotRqd()
        execStep8ProcessMakeCredUvNotRqdElse()
        // Step 9: enterpriseAttestation — not implemented
        execStep10CheckUvNotRequired()

        if (!uvNotRequired) {
            execStep11ProcessUserVerification()
        }

        execStep12ValidateExcludeList()
        // Step 13: built-in UV evidence sets UP — handled within Step 14 consent flow
        execStep14RequestUserConsent()
        execStep15ProcessExtensions()
        val response = execStep16to19GenerateCredentialAndAttestation()
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
    //spec|   Request evidence of user interaction in an authenticator-specific way (e.g., flash the LED light).
    //spec|   If the user declines permission, or the operation times out, then end the operation by returning CTAP2_ERR_OPERATION_DENIED.
    //spec|   If evidence of user interaction is provided in this step then return either
    //spec|   CTAP2_ERR_PIN_NOT_SET if PIN is not set or CTAP2_ERR_PIN_INVALID if PIN has been set.
    //
    // @see https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-makeCred-authnr-alg
    private suspend fun execStep1ZeroLengthPinUvAuthParam() {
        if (pinAuth != null && pinAuth.isEmpty()) {
            //spec| Request evidence of user interaction in an authenticator-specific way (e.g., flash the LED light).
            //spec| If the user declines permission, or the operation times out, then end the operation by returning CTAP2_ERR_OPERATION_DENIED.
            val consent = requestUserConsent()
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
    // @see https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-makeCred-authnr-alg
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

    //spec| Step 3. Validate pubKeyCredParams with the following steps:
    //spec|   For each element of pubKeyCredParams:
    //spec|     If the element specifies an algorithm that is supported by the authenticator, and no algorithm has yet been chosen by this loop, then let the algorithm specified by the current element be the chosen algorithm.
    //spec|   If the loop completes and no algorithm was chosen then return CTAP2_ERR_UNSUPPORTED_ALGORITHM.
    //
    // @see https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-makeCred-authnr-alg
    private fun execStep3ValidatePubKeyCredParams() {
        algorithmIdentifier =
            pubKeyCredParams.firstOrNull { it.type == PublicKeyCredentialType.PUBLIC_KEY && authenticatorPropertyStore.supports(it.alg) }?.alg
                ?: throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_UNSUPPORTED_ALGORITHM)
    }

    //spec| Step 5. If the options parameter is present, process all option keys and values present in the parameter.
    //spec| Treat any option keys that are not understood as absent.
    //spec| Note: As this specification defines normative behaviours for the "rk", "up", and "uv" option keys,
    //spec| they MUST be understood by all authenticators.
    //spec|   If the "uv" option is absent, let the "uv" option be treated as being present with the value false. (This is the default)
    //spec|   If the pinUvAuthParam is present, let the "uv" option be treated as being present with the value false.
    //spec|   If the "uv" option is true then:
    //spec|     If the authenticator does not support a built-in user verification method end the operation by returning CTAP2_ERR_INVALID_OPTION.
    //spec|     If the built-in user verification method has not yet been enabled, end the operation by returning CTAP2_ERR_INVALID_OPTION.
    //spec|   If the "up" option is present then:
    //spec|     If the "up" option is false, end the operation by returning CTAP2_ERR_INVALID_OPTION.
    //spec|   If the "up" option is absent, let the "up" option be treated as being present with the value true
    //spec|   (i.e., this is the default for both CTAP2.0 and CTAP2.1 authenticators).
    //
    // @see https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-makeCred-authnr-alg
    private fun execStep5ProcessOptions() {
        when (val requestOptions = options) {
            null -> {
                //spec| If the "rk" option is absent, let the "rk" option be treated as being present with the value false. (This is the default.)
                residentKeyPlan = ctapAuthenticatorSession.residentKey == ResidentKeySetting.ALWAYS
            }
            else -> {
                //spec| If the "up" option is present then:
                //spec|   If the "up" option is false, end the operation by returning CTAP2_ERR_INVALID_OPTION.
                if (requestOptions.up == false) {
                    throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_INVALID_OPTION)
                }
                residentKeyPlan = when (requestOptions.rk) {
                    true -> when (ctapAuthenticatorSession.residentKey) {
                        ResidentKeySetting.NEVER -> throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_UNSUPPORTED_OPTION)
                        else -> true
                    }
                    else -> ctapAuthenticatorSession.residentKey == ResidentKeySetting.ALWAYS
                }
                //spec| If the pinUvAuthParam is present, let the "uv" option be treated as being present with the value false.
                userVerificationPlan = if (pinAuth != null) {
                    false
                } else {
                    when (requestOptions.uv) {
                        //spec| If the "uv" option is true then:
                        //spec|   If the authenticator does not support a built-in user verification method end the operation by returning CTAP2_ERR_INVALID_OPTION.
                        //spec|   If the built-in user verification method has not yet been enabled, end the operation by returning CTAP2_ERR_INVALID_OPTION.
                        true -> {
                            when (ctapAuthenticatorSession.userVerification) {
                                UserVerificationSetting.READY -> true
                                else -> throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_INVALID_OPTION)
                            }
                        }
                        //spec| If the "uv" option is absent, let the "uv" option be treated as being present with the value false. (This is the default)
                        else -> false
                    }
                }
            }
        }
        //spec| If the "up" option is absent, let the "up" option be treated as being present with the value true
        //spec| (i.e., this is the default for both CTAP2.0 and CTAP2.1 authenticators).
        userPresencePlan = when (ctapAuthenticatorSession.userPresence) {
            UserPresenceSetting.SUPPORTED -> true
            else -> throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_INVALID_OPTION)
        }
    }

    //spec| Step 6. If the alwaysUv option ID is present and true then:
    //spec|   6.1 Let the makeCredUvNotRqd option ID be treated as false.
    //spec|   6.2 If the authenticator is not protected by some form of user verification:
    //spec|     If the clientPin option ID is present and noMcGaPermissionsWithClientPin option ID is absent or false
    //spec|     (clientPin is supported for the mc permission):
    //spec|       End the operation by returning CTAP2_ERR_PUAT_REQUIRED.
    //spec|     Else (clientPin is not supported):
    //spec|       End the operation by returning CTAP2_ERR_OPERATION_DENIED.
    //spec|   6.3 If the pinUvAuthParam is not present, and the uv option ID is true,
    //spec|   let the "uv" option be treated as being present with the value true.
    //spec|   6.4 If the pinUvAuthParam is not present, and the "uv" option is false or absent:
    //spec|     If the clientPin option ID is present and noMcGaPermissionsWithClientPin option ID is absent or false
    //spec|     (clientPin is supported for the mc permission):
    //spec|       End the operation by returning CTAP2_ERR_PUAT_REQUIRED.
    //spec|     Else (clientPin is not supported):
    //spec|       End the operation by returning CTAP2_ERR_OPERATION_DENIED.
    //
    // @see https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-makeCred-authnr-alg
    private fun execStep6ProcessAlwaysUv() {
        if (ctapAuthenticatorSession.alwaysUv != AlwaysUvSetting.ENABLED) return

        //spec| 6.1 Let the makeCredUvNotRqd option ID be treated as false.
        // (effectiveMakeCredUvNotRqd is computed in Step 7/8/10 using alwaysUv flag)

        //spec| 6.2 If the authenticator is not protected by some form of user verification:
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

        //spec| 6.3 If the pinUvAuthParam is not present, and the uv option ID is true,
        //spec| let the "uv" option be treated as being present with the value true.
        // (userVerificationPlan is already true from Step 5 when uv=true)

        //spec| 6.4 If the pinUvAuthParam is not present, and the "uv" option is false or absent:
        if (pinAuth == null && !userVerificationPlan) {
            if (ctapAuthenticatorSession.clientPIN == ClientPINSetting.ENABLED) {
                throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_PUAT_REQUIRED)
            } else {
                throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_OPERATION_DENIED)
            }
        }
    }

    //spec| Step 7. If the makeCredUvNotRqd option ID is present and set to true in the authenticatorGetInfo response:
    //spec|   If the following statements are all true:
    //spec|     The authenticator is protected by some form of user verification.
    //spec|     The "uv" option is set to false.
    //spec|     The pinUvAuthParam parameter is not present.
    //spec|     The "rk" option is present and set to true.
    //spec|   Then:
    //spec|     If ClientPin option ID is true and the noMcGaPermissionsWithClientPin option ID is absent or false,
    //spec|     end the operation by returning CTAP2_ERR_PUAT_REQUIRED.
    //spec|     Otherwise, end the operation by returning CTAP2_ERR_OPERATION_DENIED.
    //
    // @see https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-makeCred-authnr-alg
    private fun execStep7ProcessMakeCredUvNotRqd() {
        val effectiveMakeCredUvNotRqd = if (ctapAuthenticatorSession.alwaysUv == AlwaysUvSetting.ENABLED) false else ctapAuthenticatorSession.makeCredUvNotRqd == MakeCredUvNotRqdSetting.ENABLED
        if (!effectiveMakeCredUvNotRqd) return

        if (isProtectedByUserVerification && !userVerificationPlan && pinAuth == null && residentKeyPlan) {
            if (ctapAuthenticatorSession.isClientPINReady) {
                throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_PUAT_REQUIRED)
            } else {
                throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_OPERATION_DENIED)
            }
        }
    }

    //spec| Step 8. Else: (the makeCredUvNotRqd option ID in authenticatorGetInfo's response is present with the value false or is absent):
    //spec|   If the following statements are all true:
    //spec|     The authenticator is protected by some form of user verification.
    //spec|     The "uv" option is set to false.
    //spec|     The pinUvAuthParam parameter is not present.
    //spec|   Then:
    //spec|     If the ClientPin option ID is true and the noMcGaPermissionsWithClientPin option ID is absent or false,
    //spec|     end the operation by returning CTAP2_ERR_PUAT_REQUIRED.
    //spec|     Otherwise, end the operation by returning CTAP2_ERR_OPERATION_DENIED.
    //
    // @see https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-makeCred-authnr-alg
    private fun execStep8ProcessMakeCredUvNotRqdElse() {
        val effectiveMakeCredUvNotRqd = if (ctapAuthenticatorSession.alwaysUv == AlwaysUvSetting.ENABLED) false else ctapAuthenticatorSession.makeCredUvNotRqd == MakeCredUvNotRqdSetting.ENABLED
        if (effectiveMakeCredUvNotRqd) return

        if (isProtectedByUserVerification && !userVerificationPlan && pinAuth == null) {
            if (ctapAuthenticatorSession.isClientPINReady) {
                throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_PUAT_REQUIRED)
            } else {
                throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_OPERATION_DENIED)
            }
        }
    }

    //spec| Step 10. If the following statements are all true:
    //spec|   "rk" and "uv" options are both set to false or omitted.
    //spec|   the makeCredUvNotRqd option ID in authenticatorGetInfo's response is present with the value true.
    //spec|   the pinUvAuthParam parameter is not present.
    //spec| Then go to Step 12.
    //
    // @see https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-makeCred-authnr-alg
    private fun execStep10CheckUvNotRequired() {
        val effectiveMakeCredUvNotRqd = if (ctapAuthenticatorSession.alwaysUv == AlwaysUvSetting.ENABLED) false else ctapAuthenticatorSession.makeCredUvNotRqd == MakeCredUvNotRqdSetting.ENABLED
        if (!residentKeyPlan && !userVerificationPlan && effectiveMakeCredUvNotRqd && pinAuth == null) {
            uvNotRequired = true
        }
    }

    //spec| Step 11. If the authenticator is protected by some form of user verification, then:
    //spec|   11.1 If pinUvAuthParam parameter is present (implying the "uv" option is false (see Step 5)):
    //spec|     Call verify(pinUvAuthToken, clientDataHash, pinUvAuthParam).
    //spec|     If the verification returns error, then end the operation by returning CTAP2_ERR_PIN_AUTH_INVALID error.
    //spec|     Verify that the pinUvAuthToken has the mc permission, if not, then end the operation by returning CTAP2_ERR_PIN_AUTH_INVALID.
    //spec|     If the pinUvAuthToken has a permissions RP ID associated:
    //spec|       If the permissions RP ID does not match the rp.id in this request, then end the operation by returning CTAP2_ERR_PIN_AUTH_INVALID.
    //spec|     Let userVerifiedFlagValue be the result of calling getUserVerifiedFlagValue().
    //spec|     If userVerifiedFlagValue is false then end the operation by returning CTAP2_ERR_PIN_AUTH_INVALID.
    //spec|     If userVerifiedFlagValue is true then set the "uv" bit to true in the response.
    //spec|     If the pinUvAuthToken does not have a permissions RP ID associated:
    //spec|       Associate the request's rp.id parameter value with the pinUvAuthToken as its permissions RP ID.
    //spec|     Go to Step 12.
    //spec|   11.2 If the "uv" option is present and set to true (implying the pinUvAuthParam parameter is not present,
    //spec|   and that the authenticator supports an enabled built-in user verification method, see Step 5):
    //spec|     Let internalRetry be true.
    //spec|     Let uvState be the result of calling performBuiltInUv(internalRetry)
    //spec|     If uvState is error:
    //spec|       If the error reason is a user action timeout, then return CTAP2_ERR_USER_ACTION_TIMEOUT.
    //spec|       If the uvRetries counter is 0, return CTAP2_ERR_PIN_BLOCKED.
    //spec|       Otherwise, end the operation by returning CTAP2_ERR_OPERATION_DENIED.
    //spec|     If uvState is success:
    //spec|       Set the "uv" bit to true in the response.
    //
    // @see https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-makeCred-authnr-alg
    private fun execStep11ProcessUserVerification() {
        if (!isProtectedByUserVerification) return

        //spec| 11.1 If pinUvAuthParam parameter is present (implying the "uv" option is false (see Step 5)):
        if (pinAuth != null && pinProtocol != null) {
            //spec| Call verify(pinUvAuthToken, clientDataHash, pinUvAuthParam).
            //spec| If the verification returns error, then end the operation by returning CTAP2_ERR_PIN_AUTH_INVALID error.
            val protocol = ctapAuthenticatorSession.pinUvAuthManager.pinUvAuthProtocols.firstOrNull { protocol ->
                protocol.verify(protocol.pinUvAuthToken, clientDataHash, pinAuth)
            } ?: throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_PIN_AUTH_INVALID)

            //spec| Verify that the pinUvAuthToken has the mc permission, if not, then end the operation by returning CTAP2_ERR_PIN_AUTH_INVALID.
            if (!protocol.tokenState.hasPermission(PinUvAuthTokenPermission.MC)) {
                throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_PIN_AUTH_INVALID)
            }

            //spec| If the pinUvAuthToken has a permissions RP ID associated:
            //spec|   If the permissions RP ID does not match the rp.id in this request, then end the operation by returning CTAP2_ERR_PIN_AUTH_INVALID.
            val tokenRpId = protocol.tokenState.permissionsRpId
            if (tokenRpId != null && rpId != null && tokenRpId != rpId) {
                throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_PIN_AUTH_INVALID)
            }

            //spec| Let userVerifiedFlagValue be the result of calling getUserVerifiedFlagValue().
            //spec| If userVerifiedFlagValue is false then end the operation by returning CTAP2_ERR_PIN_AUTH_INVALID.
            if (!protocol.tokenState.getUserVerifiedFlagValue()) {
                throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_PIN_AUTH_INVALID)
            }

            //spec| If userVerifiedFlagValue is true then set the "uv" bit to true in the response.
            userVerificationResult = true

            //spec| If the pinUvAuthToken does not have a permissions RP ID associated:
            //spec|   Associate the request's rp.id parameter value with the pinUvAuthToken as its permissions RP ID.
            if (protocol.tokenState.permissionsRpId == null && rpId != null) {
                protocol.tokenState.permissionsRpId = rpId
            }

            protocol.tokenState.recordPlatformUsage()
            matchedProtocol = protocol
            //spec| Go to Step 12.
            return
        }

        //spec| 11.2 If the "uv" option is present and set to true (implying the pinUvAuthParam parameter is not present,
        //spec| and that the authenticator supports an enabled built-in user verification method, see Step 5):
        // Built-in UV is handled via the consent flow in Step 14.
        // userVerificationPlan remains true and will be processed during consent.
    }

    //spec| Step 12. If the excludeList parameter is present and contains a credential ID created by this authenticator,
    //spec| that is bound to the specified rp.id:
    //spec|   If the credential's credProtect value is not userVerificationRequired, then:
    //spec|     Wait for user presence.
    //spec|     Regardless of whether user presence is obtained or the authenticator times out,
    //spec|     terminate this procedure and return CTAP2_ERR_CREDENTIAL_EXCLUDED.
    //
    // @see https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-makeCred-authnr-alg
    private suspend fun execStep12ValidateExcludeList() {
        excludeList.let {
            if (it != null && it.isNotEmpty()) {
                val rpId = rp.id
                val userCredentials = authenticatorPropertyStore.loadUserCredentials(rpId)
                val residentMatch = userCredentials.any { credentialSource ->
                    it.any { descriptor ->
                        Arrays.equals(descriptor.id, credentialSource.credentialId)
                    }
                }
                val nonResidentMatch = !residentMatch && it.any { descriptor ->
                    isKnownCredentialId(descriptor, rpId)
                }
                if (residentMatch || nonResidentMatch) {
                    val makeCredentialConsentRequest = MakeCredentialConsentRequest(
                        rp,
                        user,
                        isUserPresence = true,
                        isUserVerification = false
                    )
                    ctapAuthenticatorSession.withUserPresenceWait {
                        ctapAuthenticatorSession.userVerificationHandler.onMakeCredentialConsentRequested(
                            makeCredentialConsentRequest
                        )
                    }
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
    //spec|   Set the "up" bit to true in the response.
    //spec|   Go to Step 15
    //
    // @see https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-makeCred-authnr-alg
    private fun execStep13SetUpFromBuiltInUv(): Boolean {
        if (uvPerformedViaBuiltIn) {
            userPresenceResult = true
            return true
        }
        return false
    }

    //spec| Step 14. If the "up" option is set to true:
    //spec|   If the pinUvAuthParam parameter is present then:
    //spec|     Let userPresentFlagValue be the result of calling getUserPresentFlagValue().
    //spec|     If userPresentFlagValue is false:
    //spec|       Request evidence of user interaction in an authenticator-specific way (e.g., flash the LED light).
    //spec|       If the authenticator has a display, show the items contained within the user and rp parameter structures to the user,
    //spec|       and request permission to create a credential.
    //spec|       If the user declines permission, or the operation times out, then end the operation by returning CTAP2_ERR_OPERATION_DENIED.
    //spec|   Else (implying the pinUvAuthParam parameter is not present):
    //spec|     If the "up" bit is false in the response:
    //spec|       Request evidence of user interaction in an authenticator-specific way (e.g., flash the LED light).
    //spec|       If the authenticator has a display, show the items contained within the user and rp parameter structures to the user,
    //spec|       and request permission to create a credential.
    //spec|       If the user declines permission, or the operation times out, then end the operation by returning CTAP2_ERR_OPERATION_DENIED.
    //spec|   Set the "up" bit to true in the response.
    //spec|   Call clearUserPresentFlag(), clearUserVerifiedFlag(), and clearPinUvAuthTokenPermissionsExceptLbw().
    //
    // @see https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-makeCred-authnr-alg
    private suspend fun execStep14RequestUserConsent() {
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
                val consent = requestUserConsent()
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

    private suspend fun requestUserConsent(): Boolean{
        val makeCredentialConsentRequest = MakeCredentialConsentRequest(
            rp,
            user,
            userPresencePlan,
            userVerificationPlan
        )
        return ctapAuthenticatorSession.withUserPresenceWait {
            ctapAuthenticatorSession.userVerificationHandler.onMakeCredentialConsentRequested(makeCredentialConsentRequest)
        }
    }

    //spec| Step 15. If the extensions parameter is present:
    //spec|   Process any extensions that this authenticator supports, ignoring any that it does not support.
    //spec|   Authenticator extension outputs generated by the authenticator extension processing
    //spec|   are returned in the authenticator data.
    //spec|   The set of keys in the authenticator extension outputs map MUST be equal to, or a subset of, the keys of the authenticator extension inputs map.
    //
    // @see https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-makeCred-authnr-alg
    private fun execStep15ProcessExtensions() {
        val inputs = this.registrationExtensionAuthenticatorInputs
        val outputsBuilder = AuthenticationExtensionsAuthenticatorOutputs.BuilderForRegistration()
        if(inputs != null){
            ctapAuthenticatorSession.extensionProcessors.filterIsInstance<RegistrationExtensionProcessor>().forEach{ processor ->
                if(processor.supportsRegistrationExtension(inputs)){
                    val context = RegistrationExtensionContext(ctapAuthenticatorSession, authenticatorMakeCredentialRequest)
                    processor.processRegistrationExtension(context, userCredentialBuilder, outputsBuilder)
                }
            }
            registrationExtensionAuthenticatorOutputs = outputsBuilder.build()
        }
    }

    //spec| Step 16. Generate a new credential key pair for the algorithm chosen in step 3.
    //spec| Step 17. If the "rk" option is set to true:
    //spec|   The authenticator MUST create a discoverable credential.
    //spec|   If a credential for the same rp.id and account ID already exists on the authenticator:
    //spec|     Overwrite that credential.
    //spec|   Store the user parameter along with the newly-created key pair.
    //spec|   If authenticator does not have enough internal storage to persist the new credential, return CTAP2_ERR_KEY_STORE_FULL.
    //spec| Step 18. Otherwise, if the "rk" option is false: the authenticator MUST create a non-discoverable credential.
    //spec| Step 19. If the authenticator doesn't support multiple attestation formats or the attestationFormatsPreference is absent or its value is the empty list,
    //spec|   generate an attestation statement for the newly-created credential using clientDataHash.
    //
    // @see https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-makeCred-authnr-alg
    private suspend fun execStep16to19GenerateCredentialAndAttestation(): AuthenticatorMakeCredentialResponse {
        val userCredential = createUserCredential()
        val rpIdHash = MessageDigestUtil.createSHA256().digest(rpId!!.toByteArray())
        val alg = COSEAlgorithmIdentifier.ES256 // Attestation statement is fixed to ES256 for now
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
            residentKeyPlan,
            userCredential.credentialKey,
            authenticatorDataProvider
        )

        @Suppress("ConvertSecondaryConstructorToPrimary")
        val attestationStatement: AttestationStatement =
            ctapAuthenticatorSession.attestationStatementProvider.provide(attestationStatementRequest)
        try {
            val responseData = AuthenticatorMakeCredentialResponseData(
                attestationStatementRequest.authenticatorData,
                attestationStatement
            )
            if (userCredential is ResidentUserCredential) {
                try {
                    removeExistingCredentialForSameAccount(userCredential)
                    authenticatorPropertyStore.saveUserCredential(userCredential)
                } catch (e: StoreFullException) {
                    throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_KEY_STORE_FULL)
                }
            }
            return AuthenticatorMakeCredentialResponse(CtapStatusCode.CTAP2_OK, responseData)
        } catch (e: java.lang.RuntimeException) {
            if (userCredential is ResidentUserCredential) {
                removeInCompleteUserCredential(userCredential)
            }
            throw e
        }
    }

    private fun createUserCredential(): UserCredential {

        if (!authenticatorPropertyStore.supports(algorithmIdentifier)) {
            throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_UNSUPPORTED_ALGORITHM)
        }

        val credentialKey: CredentialKey
        if (residentKeyPlan) {
            val credentialId = ByteArray(32)
            secureRandom.nextBytes(credentialId)
            userCredentialBuilder.credentialId(credentialId)

            try {
                credentialKey = authenticatorPropertyStore.createUserCredentialKey(
                    algorithmIdentifier,
                    clientDataHash
                )
            } catch (e: StoreFullException) {
                throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_KEY_STORE_FULL, e)
            }
        } else {
            credentialKey = NonResidentCredentialKey(
                algorithmIdentifier.toSignatureAlgorithm(),
                createCredentialKeyPair(algorithmIdentifier)
            )
        }
        userCredentialBuilder.userCredentialKey(credentialKey)
        userCredentialBuilder.createdAt(Instant.now())
        return userCredentialBuilder.build()
    }

    private fun removeExistingCredentialForSameAccount(newCredential: ResidentUserCredential) {
        val existingCredentials = authenticatorPropertyStore.loadUserCredentials(newCredential.rpId)
        existingCredentials
            .filter { Arrays.equals(it.userHandle, newCredential.userHandle) }
            .forEach { authenticatorPropertyStore.removeUserCredential(it.credentialId) }
    }

    private fun removeInCompleteUserCredential(userCredential: ResidentUserCredential?) {
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
            MessageDigestUtil.createSHA256().digest(rpId!!.toByteArray(StandardCharsets.UTF_8))
        var flag = AuthenticatorData.BIT_AT
        if (userPresenceResult) flag = flag or AuthenticatorData.BIT_UP
        if (userVerificationResult) flag = flag or AuthenticatorData.BIT_UV
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
