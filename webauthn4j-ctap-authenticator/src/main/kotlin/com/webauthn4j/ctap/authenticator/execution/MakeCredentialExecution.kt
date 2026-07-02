package com.webauthn4j.ctap.authenticator.execution


import tools.jackson.dataformat.cbor.CBORMapper
import com.webauthn4j.ctap.authenticator.CtapAuthenticatorSession
import com.webauthn4j.ctap.authenticator.MakeCredentialConsentRequest
import com.webauthn4j.ctap.authenticator.UserCredentialBuilder
import com.webauthn4j.ctap.authenticator.attestation.AttestationStatementRequest
import com.webauthn4j.ctap.authenticator.data.credential.CredentialKey
import com.webauthn4j.ctap.authenticator.data.credential.NonResidentCredentialKey
import com.webauthn4j.ctap.authenticator.data.credential.NonResidentUserCredentialSource
import com.webauthn4j.ctap.authenticator.data.credential.ResidentUserCredential
import com.webauthn4j.ctap.authenticator.data.credential.UserCredential
import com.webauthn4j.ctap.authenticator.data.event.MakeCredentialEvent
import com.webauthn4j.ctap.authenticator.data.settings.ResidentKeySetting
import com.webauthn4j.ctap.authenticator.data.settings.UserPresenceSetting
import com.webauthn4j.ctap.authenticator.data.settings.UserVerificationSetting
import com.webauthn4j.ctap.authenticator.extension.RegistrationExtensionContext
import com.webauthn4j.ctap.authenticator.extension.RegistrationExtensionProcessor
import com.webauthn4j.ctap.authenticator.internal.KeyPairUtil.createCredentialKeyPair
import com.webauthn4j.ctap.authenticator.store.AuthenticatorPropertyStore
import com.webauthn4j.ctap.authenticator.store.StoreFullException
import com.webauthn4j.ctap.core.data.*
import com.webauthn4j.data.PinProtocolVersion
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
    private var userVerificationResult = false
    private var userPresenceResult = false
    private lateinit var algorithmIdentifier: COSEAlgorithmIdentifier

    private var registrationExtensionAuthenticatorOutputs: AuthenticationExtensionsAuthenticatorOutputs<RegistrationExtensionAuthenticatorOutput> = AuthenticationExtensionsAuthenticatorOutputs()

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

        // Step 1: TODO: CTAP 2.1 - zero length pinUvAuthParam handling
        //spec| Step 1. If authenticator supports either pinUvAuthToken or clientPin features and the platform sends a zero length pinUvAuthParam:
        // execStep1ZeroLengthPinUvAuthParam()

        // Step 2: TODO: CTAP 2.1 - pinUvAuthProtocol validation
        //spec| Step 2. If the pinUvAuthParam parameter is present:
        // execStep2ValidatePinUvAuthProtocol()

        execStep3ValidatePubKeyCredParams()

        // Step 4: TODO: CTAP 2.1 - initialize response structure
        //spec| Step 4. Create a new authenticatorMakeCredential response structure and initialize both its "uv" bit and "up" bit as false.
        // execStep4InitializeResponseStructure()

        execStep5ProcessOptions()

        // Step 6: TODO: CTAP 2.1 - alwaysUv processing
        //spec| Step 6. If the alwaysUv option ID is present and true then:
        // execStep6ProcessAlwaysUv()

        // Step 7: TODO: CTAP 2.1 - makeCredUvNotRqd (present and true)
        //spec| Step 7. If the makeCredUvNotRqd option ID is present and set to true in the authenticatorGetInfo response:
        // execStep7ProcessMakeCredUvNotRqd()

        // Step 8: TODO: CTAP 2.1 - makeCredUvNotRqd (absent or false)
        //spec| Step 8. Else: (the makeCredUvNotRqd option ID in authenticatorGetInfo's response is present with the value false or is absent):
        // execStep8ProcessMakeCredUvNotRqdElse()

        // Step 9: TODO: CTAP 2.1 - enterprise attestation
        //spec| Step 9. If the enterpriseAttestation parameter is present:
        // execStep9ProcessEnterpriseAttestation()

        // Step 10: TODO: CTAP 2.1 - UV not required check
        //spec| Step 10. If the following statements are all true:
        // execStep10CheckUvNotRequired()

        execStep11ProcessUserVerification()
        execStep12ValidateExcludeList()

        // Step 13: TODO: CTAP 2.1 - set up from built-in UV
        //spec| Step 13. If evidence of user interaction was provided as part of Step 11 (i.e., by invoking performBuiltInUv()):
        // execStep13SetUpFromBuiltInUv()

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


    //spec| Step 3. Validate pubKeyCredParams with the following steps:
    //spec| For each element of pubKeyCredParams:
    //spec| If the element specifies an algorithm that is supported by the authenticator, and no algorithm has yet been chosen by this loop, then let the algorithm specified by the current element be the chosen algorithm.
    //spec| If the loop completes and no algorithm was chosen then return CTAP2_ERR_UNSUPPORTED_ALGORITHM.
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
    //
    // @see https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-makeCred-authnr-alg
    private fun execStep5ProcessOptions() {
        when (val requestOptions = options) {
            null -> {
                residentKeyPlan = ctapAuthenticatorSession.residentKey == ResidentKeySetting.ALWAYS
            }
            else -> {
                if(requestOptions.up == false){
                    throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_UNSUPPORTED_OPTION)
                }
                residentKeyPlan = when (requestOptions.rk) {
                    true -> when (ctapAuthenticatorSession.residentKey) {
                        ResidentKeySetting.NEVER -> throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_UNSUPPORTED_OPTION)
                        else -> true
                    }
                    else -> ctapAuthenticatorSession.residentKey == ResidentKeySetting.ALWAYS
                }
                userVerificationPlan = when (requestOptions.uv) {
                    true -> {
                        when (ctapAuthenticatorSession.userVerification) {
                            UserVerificationSetting.READY -> true
                            else -> throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_UNSUPPORTED_OPTION)
                        }
                    }
                    else -> false
                }
            }
        }
        userPresencePlan = when (ctapAuthenticatorSession.userPresence) {
            UserPresenceSetting.SUPPORTED -> true
            else -> throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_UNSUPPORTED_OPTION)
        }
    }

    //spec| Step 11. If the authenticator is protected by some form of user verification, then:
    //spec| If pinUvAuthParam parameter is present (implying the "uv" option is false (see Step 5)):
    //spec| Call verify(pinUvAuthToken, clientDataHash, pinUvAuthParam).
    //spec| If the verification returns error, then end the operation by returning CTAP2_ERR_PIN_AUTH_INVALID error.
    //spec| If the "uv" option is present and set to true (implying the pinUvAuthParam parameter is not present,
    //spec| and that the authenticator supports an enabled built-in user verification method, see Step 5):
    //
    // This method merges the CTAP 2.0 steps 5 (pinAuth processing), 6 (clientPin validation),
    // and 7 (pinProtocol validation) into a single user verification step aligned with CTAP 2.3.
    //
    // @see https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-makeCred-authnr-alg
    private suspend fun execStep11ProcessUserVerification() {
        // Process pinAuth (formerly CTAP 2.0 Step 5)
        pinAuth.let {
            if (it != null && pinProtocol == PinProtocolVersion.VERSION_1) {
                // Handle zero length pinAuth for authenticator selection
                if (it.isEmpty()) {
                    requestUserConsent()
                    if (ctapAuthenticatorSession.pinUvAuthService.isClientPINReady) {
                        throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_PIN_INVALID)
                    } else {
                        throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_PIN_NOT_SET)
                    }
                } else {
                    ctapAuthenticatorSession.pinUvAuthService.verifyPinUvAuthParam(it, clientDataHash)
                    userPresenceResult = true
                    userVerificationResult = true
                }
            }
        }

        // Validate clientPin requirement (formerly CTAP 2.0 Step 6)
        //TODO: to be fixed to align CTAP2.1 spec.
//        if (authenticatorMakeCredentialRequest.pinAuth == null && ctapAuthenticatorSession.pinUvAuthService.clientPIN != null) {
//            throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_PIN_REQUIRED)
//        }

        // Validate pinProtocol (formerly CTAP 2.0 Step 7)
        if (authenticatorMakeCredentialRequest.pinAuth != null && authenticatorMakeCredentialRequest.pinProtocol != PinProtocolVersion.VERSION_1) {
            throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_PIN_AUTH_INVALID)
        }
    }

    //spec| Step 12. If the excludeList parameter is present and contains a credential ID created by this authenticator,
    //spec| that is bound to the specified rp.id:
    //spec| If the credential's credProtect value is not userVerificationRequired, then:
    //spec| Wait for user presence.
    //spec| Regardless of whether user presence is obtained or the authenticator times out,
    //spec| terminate this procedure and return CTAP2_ERR_CREDENTIAL_EXCLUDED.
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

    //spec| Step 14. If the "up" option is set to true:
    //spec| If the pinUvAuthParam parameter is present then:
    //spec| Let userPresentFlagValue be the result of calling getUserPresentFlagValue().
    //spec| If userPresentFlagValue is false:
    //spec| Request evidence of user interaction in an authenticator-specific way (e.g., flash the LED light).
    //spec| If the authenticator has a display, show the items contained within the user and rp parameter structures to the user, and request permission to create a credential.
    //spec| If the user declines permission, or the operation times out, then end the operation by returning CTAP2_ERR_OPERATION_DENIED.
    //spec| Else (implying the pinUvAuthParam parameter is not present):
    //spec| If the "up" bit is false in the response:
    //spec| Request evidence of user interaction in an authenticator-specific way (e.g., flash the LED light).
    //spec| If the authenticator has a display, show the items contained within the user and rp parameter structures to the user, and request permission to create a credential.
    //spec| If the user declines permission, or the operation times out, then end the operation by returning CTAP2_ERR_OPERATION_DENIED.
    //spec| Set the "up" bit to true in the response.
    //
    // @see https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-makeCred-authnr-alg
    private suspend fun execStep14RequestUserConsent() {
        val consent: Boolean = requestUserConsent()
        if (consent) {
            if (userPresencePlan) {
                userPresenceResult = true
            }
            if (userVerificationPlan) {
                userVerificationResult = true
            }
        } else {
            throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_OPERATION_DENIED)
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
    //spec| Process any extensions that this authenticator supports, ignoring any that it does not support.
    //spec| Authenticator extension outputs generated by the authenticator extension processing
    //spec| are returned in the authenticator data.
    //spec| The set of keys in the authenticator extension outputs map MUST be equal to, or a subset of, the keys of the authenticator extension inputs map.
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
    //spec| The authenticator MUST create a discoverable credential.
    //spec| If a credential for the same rp.id and account ID already exists on the authenticator:
    //spec| Overwrite that credential.
    //spec| Store the user parameter along with the newly-created key pair.
    //spec| If authenticator does not have enough internal storage to persist the new credential, return CTAP2_ERR_KEY_STORE_FULL.
    //spec| Step 18. Otherwise, if the "rk" option is false: the authenticator MUST create a non-discoverable credential.
    //spec| Step 19. If the authenticator doesn't support multiple attestation formats or the attestationFormatsPreference is absent or its value is the empty list,
    //spec| generate an attestation statement for the newly-created credential using clientDataHash.
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
