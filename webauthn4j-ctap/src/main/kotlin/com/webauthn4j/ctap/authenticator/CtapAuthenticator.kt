package com.webauthn4j.ctap.authenticator

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.dataformat.cbor.CBORFactory
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule
import com.webauthn4j.converter.AuthenticatorDataConverter
import com.webauthn4j.converter.util.ObjectConverter
import com.webauthn4j.ctap.authenticator.attestation.AttestationStatementGenerator
import com.webauthn4j.ctap.authenticator.attestation.NoneAttestationStatementGenerator
import com.webauthn4j.ctap.authenticator.event.Event
import com.webauthn4j.ctap.authenticator.settings.*
import com.webauthn4j.ctap.authenticator.store.AuthenticatorPropertyStore
import com.webauthn4j.ctap.authenticator.store.InMemoryAuthenticatorPropertyStore
import com.webauthn4j.ctap.authenticator.store.UserCredential
import com.webauthn4j.ctap.core.converter.jackson.CtapCBORModule
import com.webauthn4j.ctap.core.converter.jackson.PublicKeyCredentialSourceCBORModule
import com.webauthn4j.ctap.core.data.*
import com.webauthn4j.data.AuthenticatorTransport
import com.webauthn4j.data.attestation.authenticator.AAGUID
import org.slf4j.LoggerFactory
import java.io.Serializable
import java.lang.Exception

class CtapAuthenticator @JvmOverloads constructor(
    // Core logic delegates
    // These are final as it should not be updated on the fly for integrity. To update these, new instance should be created.
    val attestationStatementGenerator: AttestationStatementGenerator = NoneAttestationStatementGenerator(),
    // Handlers
    var authenticatorPropertyStore: AuthenticatorPropertyStore<Serializable?> = InMemoryAuthenticatorPropertyStore(),
    val objectConverter: ObjectConverter = createObjectConverter(),
    settings: CtapAuthenticatorSettings = CtapAuthenticatorSettings()
) {


    companion object {
        @JvmField
        val AAGUID = AAGUID("33c1642b-b5e9-423d-9add-5a0119c2a8b8")
        const val VERSION_FIDO_2_0 = "FIDO_2_0"
        const val VERSION_FIDO_2_1_PRE = "FIDO_2_1_PRE"

        @JvmField
        val VERSIONS = listOf(VERSION_FIDO_2_0)

        @JvmField
        val PIN_PROTOCOLS = listOf(PinProtocolVersion.VERSION_1)
        val TRANSPORTS = setOf(
            AuthenticatorTransport.NFC,
            AuthenticatorTransport.BLE,
            AuthenticatorTransport.USB
        )
        val EXTENSIONS = emptyList<String>()
        private fun createObjectConverter(): ObjectConverter {
            val jsonMapper = ObjectMapper()
            val cborMapper = ObjectMapper(CBORFactory())
            cborMapper.registerModule(CtapCBORModule())
            cborMapper.registerModule(PublicKeyCredentialSourceCBORModule())
            cborMapper.registerModule(JavaTimeModule())
            return ObjectConverter(jsonMapper, cborMapper)
        }
    }

    private val logger = LoggerFactory.getLogger(CtapAuthenticator::class.java)

    val authenticatorDataConverter: AuthenticatorDataConverter =
        AuthenticatorDataConverter(objectConverter)

    // Authenticator characteristics
    // These are final as it should not be updated on the fly for integrity. To update these, new instance should be created.
    @Suppress("JoinDeclarationAndAssignment")
    val platformSetting: PlatformSetting
    val residentKeySetting: ResidentKeySetting
    val clientPINSetting: ClientPINSetting
    val resetProtectionSetting: ResetProtectionSetting
    val credentialSelectorSetting: CredentialSelectorSetting
    val userPresenceSetting: UserPresenceSetting
    val userVerificationSetting: UserVerificationSetting

    // Authenticator properties
    val aaguid: AAGUID = settings.aaguid

    val clientPINService: ClientPINService = ClientPINService(authenticatorPropertyStore)
    var onGoingGetAssertionSession: GetAssertionSession? = null
    var userConsentHandler: UserConsentHandler = DefaultUserConsentHandler()
    var credentialSelectionHandler: CredentialSelectionHandler = DefaultCredentialSelectionHandler()
    var eventListeners: MutableList<EventListener> = mutableListOf()
    var exceptionReporters: MutableList<ExceptionReporter> = mutableListOf()


    init {

        // authenticator settings
        platformSetting = settings.platform
        residentKeySetting = settings.residentKey
        clientPINSetting = settings.clientPIN
        resetProtectionSetting = settings.resetProtection
        userPresenceSetting = settings.userPresence
        userVerificationSetting = settings.userVerification
        credentialSelectorSetting = settings.credentialSelector
    }

    suspend fun <TC : CtapRequest, TR : CtapResponse<TRD>?, TRD : CtapResponseData?> invokeCommand(
        command: TC
    ): TR {
        val response = when (command) {
            is AuthenticatorMakeCredentialRequest -> makeCredential(command)
            is AuthenticatorGetAssertionRequest -> getAssertion(command)
            is AuthenticatorGetNextAssertionRequest -> getNextAssertion(command)
            is AuthenticatorGetInfoRequest -> getInfo(command)
            is AuthenticatorClientPINRequest -> clientPIN(command)
            is AuthenticatorResetRequest -> reset(command)
            else -> throw IllegalStateException(
                String.format(
                    "unknown command %s is invoked.",
                    command::class.java.toString()
                )
            )
        }
        @Suppress("UNCHECKED_CAST")
        return response as TR
    }

    suspend fun makeCredential(authenticatorMakeCredentialCommand: AuthenticatorMakeCredentialRequest): AuthenticatorMakeCredentialResponse {
        return MakeCredentialExecution(this, authenticatorMakeCredentialCommand).execute()
    }

    suspend fun getAssertion(authenticatorGetAssertionCommand: AuthenticatorGetAssertionRequest): AuthenticatorGetAssertionResponse {
        return GetAssertionExecution(this, authenticatorGetAssertionCommand).execute()
    }

    @JvmOverloads
    suspend fun getNextAssertion(authenticatorGetNextAssertionCommand: AuthenticatorGetNextAssertionRequest = AuthenticatorGetNextAssertionRequest()): AuthenticatorGetNextAssertionResponse {
        return GetNextAssertionExecution(this, authenticatorGetNextAssertionCommand).execute()
    }

    @JvmOverloads
    suspend fun getInfo(authenticatorGetInfoCommand: AuthenticatorGetInfoRequest = AuthenticatorGetInfoRequest()): AuthenticatorGetInfoResponse {
        return GetInfoExecution(this, authenticatorGetInfoCommand).execute()
    }

    suspend fun clientPIN(authenticatorClientPINCommand: AuthenticatorClientPINRequest): AuthenticatorClientPINResponse {
        return ClientPINExecution(this, authenticatorClientPINCommand).execute()
    }

    @JvmOverloads
    suspend fun reset(authenticatorResetCommand: AuthenticatorResetRequest = AuthenticatorResetRequest()): AuthenticatorResetResponse {
        return ResetExecution(this, authenticatorResetCommand).execute()
    }

    suspend fun cancel() {
        TODO("Not yet implemented")
    }

    fun registerEventListener(eventListener: EventListener) {
        eventListeners.add(eventListener)
    }

    fun unregisterEventListener(eventListener: EventListener) {
        eventListeners.remove(eventListener)
    }

    internal fun publishEvent(event: Event) {
        eventListeners.forEach { it.onEvent(event) }
    }

    fun registerExceptionReporter(exceptionReporter: ExceptionReporter){
        exceptionReporters.add(exceptionReporter)
    }

    fun unregisterExceptionReporter(exceptionReporter: ExceptionReporter){
        exceptionReporters.remove(exceptionReporter)
    }

    internal fun reportException(exception: Exception){
        exceptionReporters.forEach{ it.report(exception) }
    }

    private class DefaultUserConsentHandler : UserConsentHandler {
        override suspend fun consentMakeCredential(options: MakeCredentialConsentOptions): Boolean {
            return true
        }

        override suspend fun consentGetAssertion(options: GetAssertionConsentOptions): Boolean {
            return true
        }
    }

    private class DefaultCredentialSelectionHandler : CredentialSelectionHandler {
        override suspend fun select(list: List<UserCredential<Serializable?>>): UserCredential<Serializable?> {
            return list.first()
        }
    }

}