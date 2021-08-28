package com.webauthn4j.ctap.authenticator

import com.webauthn4j.converter.util.CborConverter
import com.webauthn4j.ctap.authenticator.attestation.AttestationStatementRequest
import com.webauthn4j.ctap.authenticator.event.MakeCredentialEvent
import com.webauthn4j.ctap.authenticator.exception.CtapCommandExecutionException
import com.webauthn4j.ctap.authenticator.exception.StoreFullException
import com.webauthn4j.ctap.authenticator.extension.RegistrationExtensionContext
import com.webauthn4j.ctap.authenticator.extension.RegistrationExtensionProcessor
import com.webauthn4j.ctap.authenticator.internal.KeyPairUtil.createCredentialKeyPair
import com.webauthn4j.ctap.authenticator.settings.ResidentKeySetting
import com.webauthn4j.ctap.authenticator.settings.UserPresenceSetting
import com.webauthn4j.ctap.authenticator.settings.UserVerificationSetting
import com.webauthn4j.ctap.authenticator.store.*
import com.webauthn4j.ctap.core.data.*
import com.webauthn4j.data.PublicKeyCredentialDescriptor
import com.webauthn4j.data.PublicKeyCredentialParameters
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
import kotlin.collections.HashMap
import kotlin.experimental.or

@Suppress("ConvertSecondaryConstructorToPrimary", "FunctionName")
internal class MakeCredentialExecution :
    CtapCommandExecutionBase<AuthenticatorMakeCredentialRequest, AuthenticatorMakeCredentialResponse> {

    override val commandName: String = "MakeCredential"

    private val logger: Logger = LoggerFactory.getLogger(MakeCredentialExecution::class.java)

    @Suppress("JoinDeclarationAndAssignment")
    private val ctapAuthenticator: CtapAuthenticator
    private val authenticatorMakeCredentialRequest: AuthenticatorMakeCredentialRequest

    private val authenticatorPropertyStore: AuthenticatorPropertyStore
    private val cborConverter: CborConverter
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
        ctapAuthenticator: CtapAuthenticator,
        authenticatorMakeCredentialCommand: AuthenticatorMakeCredentialRequest
    ) : super(ctapAuthenticator, authenticatorMakeCredentialCommand) {
        this.ctapAuthenticator = ctapAuthenticator
        this.authenticatorMakeCredentialRequest = authenticatorMakeCredentialCommand

        this.authenticatorPropertyStore = ctapAuthenticator.authenticatorPropertyStore
        this.cborConverter = ctapAuthenticator.objectConverter.cborConverter

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
        this.userCredentialBuilder = UserCredentialBuilder(ctapAuthenticator.objectConverter, authenticatorPropertyStore.loadEncryptionKey(), authenticatorPropertyStore.loadEncryptionIV())

        userCredentialBuilder.userHandle(user.id)
        userCredentialBuilder.username(user.name)
        userCredentialBuilder.displayName(user.displayName)
        userCredentialBuilder.rpId(rpId)
        userCredentialBuilder.rpName(rp.name)
        userCredentialBuilder.counter(counter)
        userCredentialBuilder.otherUI(null)
    }

    override suspend fun doExecute(): AuthenticatorMakeCredentialResponse {
        if (rpId == null) {
            throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_MISSING_PARAMETER)
        }
        execStep1ValidateExcludeList()
        execStep2ValidatePubKeyCredParams()
        execStep3ProcessOptions()
        execStep4ProcessExtensions()
        execStep5ProcessPinAuth()
        execStep6ValidateClientPin()
        execStep7ValidatePinProtocol()
        execStep8RequestUserConsent()
        val response = execStep9to11GenerateAttestedCredential()
        val event = MakeCredentialEvent(
            Instant.now(),
            rpId,
            rp.name,
            user.name,
            user.displayName,
            HashMap()
        )
        ctapAuthenticator.publishEvent(event)
        return response
    }

    override fun createErrorResponse(statusCode: CtapStatusCode): AuthenticatorMakeCredentialResponse {
        return AuthenticatorMakeCredentialResponse(statusCode)
    }


    //spec| Step1
    //spec| If the excludeList parameter is present and contains a credential ID that is present on this authenticator and bound to the specified rpId,
    //spec| wait for user presence, then terminate this procedure and return error code CTAP2_ERR_CREDENTIAL_EXCLUDED.
    //spec| User presence check is required for CTAP2 authenticators before the RP gets told that the token is already registered to behave similarly to CTAP1/U2F authenticators.
    private suspend fun execStep1ValidateExcludeList() {
        excludeList.let {
            if (it != null && it.isNotEmpty()) {
                val excludeCredentialIds = it.map { item -> item.id }
                val rpId = rp.id
                val userCredentials = authenticatorPropertyStore.loadUserCredentials(rpId)
                val match = userCredentials.any { credentialSource ->
                    excludeCredentialIds.any { item ->
                        Arrays.equals(
                            item,
                            credentialSource.credentialId
                        )
                    }
                }
                if (match) {
                    val makeCredentialConsentOptions = MakeCredentialConsentOptions(
                        rp,
                        user,
                        isUserPresence = true,
                        isUserVerification = false
                    )
                    ctapAuthenticator.userConsentHandler.consentMakeCredential(
                        makeCredentialConsentOptions
                    )
                    throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_CREDENTIAL_EXCLUDED)
                }
            }
        }
    }

    //spec| Step2
    //spec| If the pubKeyCredParams parameter does not contain a valid COSEAlgorithmIdentifier value that is supported by the authenticator,
    //spec| terminate this procedure and return error code CTAP2_ERR_UNSUPPORTED_ALGORITHM.
    private fun execStep2ValidatePubKeyCredParams() {
        algorithmIdentifier =
            pubKeyCredParams.firstOrNull { authenticatorPropertyStore.supports(it.alg) }?.alg
                ?: throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_UNSUPPORTED_ALGORITHM)
    }

    //spec| Step3
    //spec| If the options parameter is present, process all the options.
    //spec| If the option is known but not supported, terminate this procedure and return CTAP2_ERR_UNSUPPORTED_OPTION.
    //spec| If the option is known but not valid for this command, terminate this procedure and return CTAP2_ERR_INVALID_OPTION.
    //spec| Ignore any options that are not understood.
    //spec| Note that because this specification defines normative behaviors for them,
    //spec| all authenticators MUST understand the "rk", "up", and "uv" options.
    private fun execStep3ProcessOptions() {
        when (val requestOptions = options) {
            null -> {
                residentKeyPlan = ctapAuthenticator.residentKeySetting == ResidentKeySetting.ALWAYS
            }
            else -> {
                residentKeyPlan = when (requestOptions.rk) {
                    true -> when (ctapAuthenticator.residentKeySetting) {
                        ResidentKeySetting.NEVER -> throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_UNSUPPORTED_OPTION)
                        else -> true
                    }
                    else -> ctapAuthenticator.residentKeySetting == ResidentKeySetting.ALWAYS
                }
                userVerificationPlan = when (requestOptions.uv) {
                    true -> {
                        when (ctapAuthenticator.userVerificationSetting) {
                            UserVerificationSetting.READY -> true
                            else -> throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_UNSUPPORTED_OPTION)
                        }
                    }
                    else -> false
                }
            }
        }
        userPresencePlan = when (ctapAuthenticator.userPresenceSetting) {
            UserPresenceSetting.SUPPORTED -> true
            else -> throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_UNSUPPORTED_OPTION)
        }
    }

    //spec| Step4
    //spec| Optionally, if the extensions parameter is present, process any extensions that this authenticator supports.
    //spec| Authenticator extension outputs generated by the authenticator extension processing are returned in the authenticator data.
    private fun execStep4ProcessExtensions() {
        val inputs = this.registrationExtensionAuthenticatorInputs
        val outputsBuilder = AuthenticationExtensionsAuthenticatorOutputs.BuilderForRegistration()
        if(inputs != null){
            ctapAuthenticator.extensionProcessors.filterIsInstance<RegistrationExtensionProcessor>().forEach{ processor ->
                if(processor.supportsRegistrationExtension(inputs)){
                    val context = RegistrationExtensionContext(ctapAuthenticator, authenticatorMakeCredentialRequest)
                    processor.processRegistrationExtension(context, userCredentialBuilder, outputsBuilder)
                }
            }
            registrationExtensionAuthenticatorOutputs = outputsBuilder.build()
        }
    }

    //spec| Step5
    //spec| If pinAuth parameter is present and pinProtocol is 1,
    //spec| verify it by matching it against first 16 bytes of HMAC-SHA-256 of clientDataHash parameter using pinToken: HMAC- SHA-256(pinToken, clientDataHash).
    //spec|
    //spec| - If the verification succeeds, set the "uv" bit to 1 in the response.
    //spec| - If the verification fails, return CTAP2_ERR_PIN_AUTH_INVALID error.
    private suspend fun execStep5ProcessPinAuth() {
        pinAuth.let {
            if (it != null && pinProtocol == PinProtocolVersion.VERSION_1) {
                //spec| If platform sends zero length pinAuth, authenticator needs to wait for user touch
                //spec| and then returns either CTAP2_ERR_PIN_NOT_SET if pin is not set or CTAP2_ERR_PIN_INVALID if pin has been set.
                //spec| This is done for the case where multiple authenticators are attached to the platform and
                //spec| the platform wants to enforce clientPin semantics,
                //spec| but the user has to select which authenticator to send the pinToken to.
                if (it.isEmpty()) {
                    requestUserConsent()
                    if (ctapAuthenticator.clientPINService.isClientPINReady) {
                        throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_PIN_AUTH_INVALID)
                    } else {
                        throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_PIN_NOT_SET)
                    }
                } else {
                    ctapAuthenticator.clientPINService.validatePINAuth(it, clientDataHash)
                    userPresenceResult = true
                    userVerificationResult = true
                }
            }
        }
    }

    //TODO: to be fixed to align CTAP2.1 spec.
    //spec| Step6
    //spec| If pinAuth parameter is not present and clientPin been set on the authenticator, return CTAP2_ERR_PIN_REQUIRED error.
    private fun execStep6ValidateClientPin() {
//        if (authenticatorMakeCredentialRequest.pinAuth == null && ctapAuthenticator.clientPINService.clientPIN != null) {
//            throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_PIN_REQUIRED)
//        }
    }

    //spec| Step7
    //spec| If pinAuth parameter is present and the pinProtocol is not supported, return CTAP2_ERR_PIN_AUTH_INVALID.
    private fun execStep7ValidatePinProtocol() {
        if (authenticatorMakeCredentialRequest.pinAuth != null && authenticatorMakeCredentialRequest.pinProtocol != PinProtocolVersion.VERSION_1) {
            throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_PIN_AUTH_INVALID)
        }
    }

    //spec| Step8
    //spec| If the authenticator has a display, show the items contained within the user and rp parameter structures to the user.
    //spec| Alternatively, request user interaction in an authenticator-specific way (e.g., flash the LED light).
    //spec| Request permission to create a credential. If the user declines permission, return the CTAP2_ERR_OPERATION_DENIED error.
    private suspend fun execStep8RequestUserConsent() {
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
        val options = MakeCredentialConsentOptions(
            rp,
            user,
            userPresencePlan,
            userVerificationPlan
        )
        return ctapAuthenticator.userConsentHandler.consentMakeCredential(options)
    }

    //spec| Step9-11
    //spec| Generate a new credential key pair for the algorithm specified.
    //spec| If "rk" in authenticatorOptions parameter is set to true:
    //spec| - If a credential for the same RP ID and account ID already exists on the authenticator, overwrite that credential.
    //spec| - Store the user parameter along the newly-created key pair.
    //spec| - If authenticator does not have enough internal storage to persist the new credential, return CTAP2_ERR_KEY_STORE_FULL.
    //spec| Generate an attestation statement for the newly-created key using clientDataHash.
    private suspend fun execStep9to11GenerateAttestedCredential(): AuthenticatorMakeCredentialResponse {
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
            ctapAuthenticator.attestationStatementGenerator.generate(attestationStatementRequest)
        try {
            val responseData = AuthenticatorMakeCredentialResponseData(
                attestationStatementRequest.authenticatorData,
                attestationStatement
            )
            if (userCredential is ResidentUserCredential) {
                try {
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
            AttestedCredentialData(ctapAuthenticator.aaguid, credentialId, credentialPublicKey)
        return AuthenticatorData(
            rpIdHash,
            flag,
            counter,
            attestedCredentialData,
            registrationExtensionAuthenticatorOutputs
        )
    }

}