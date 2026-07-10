package com.webauthn4j.ctap.authenticator

import com.webauthn4j.converter.AuthenticatorDataConverter
import com.webauthn4j.ctap.authenticator.attestation.AttestationStatementProvider
import com.webauthn4j.ctap.authenticator.attestation.FIDOU2FAttestationStatementProvider
import com.webauthn4j.ctap.authenticator.data.event.Event
import com.webauthn4j.data.PinProtocolVersion
import com.webauthn4j.ctap.authenticator.data.settings.*
import com.webauthn4j.ctap.authenticator.execution.ClientPINExecution
import com.webauthn4j.ctap.authenticator.execution.GetAssertionExecution
import com.webauthn4j.ctap.authenticator.execution.GetInfoExecution
import com.webauthn4j.ctap.authenticator.execution.GetNextAssertionExecution
import com.webauthn4j.ctap.authenticator.execution.MakeCredentialExecution
import com.webauthn4j.ctap.authenticator.execution.ResetExecution
import com.webauthn4j.ctap.authenticator.execution.SelectionExecution
import com.webauthn4j.ctap.authenticator.execution.U2FAuthenticationExecution
import com.webauthn4j.ctap.authenticator.execution.U2FRegisterExecution
import com.webauthn4j.ctap.authenticator.extension.ExtensionProcessor
import com.webauthn4j.ctap.authenticator.store.AuthenticatorPropertyStore
import com.webauthn4j.ctap.core.data.*
import com.webauthn4j.data.AuthenticatorTransport
import com.webauthn4j.data.attestation.authenticator.AAGUID
import kotlinx.coroutines.Job
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.async
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.slf4j.LoggerFactory

/**
 * Ctap Authenticator
 */
class CtapAuthenticatorSession internal constructor(
    ctapAuthenticator: CtapAuthenticator,
    userVerificationCapabilityProvider: UserVerificationCapabilityProvider?,
    makeCredentialConsentHandler: MakeCredentialConsentHandler?,
    getAssertionConsentHandler: GetAssertionConsentHandler?,
    selectionHandler: SelectionHandler?,
) {

    private val logger = LoggerFactory.getLogger(CtapAuthenticatorSession::class.java)

    private val mutex = Mutex()

    // Core logic delegates
    val attestationStatementProvider: AttestationStatementProvider = ctapAuthenticator.attestationStatementProvider
    val fidoU2FBasicAttestationStatementGenerator: FIDOU2FAttestationStatementProvider = ctapAuthenticator.fidoU2FBasicAttestationStatementGenerator
    val transports: Set<AuthenticatorTransport> = ctapAuthenticator.transports
    val extensionProcessors: List<ExtensionProcessor> = ctapAuthenticator.extensionProcessors
    val authenticatorPropertyStore: AuthenticatorPropertyStore = ctapAuthenticator.authenticatorPropertyStore
    val userVerificationCapabilityProvider: UserVerificationCapabilityProvider = userVerificationCapabilityProvider ?: ctapAuthenticator.userVerificationCapabilityProvider
    val makeCredentialConsentHandler: MakeCredentialConsentHandler = makeCredentialConsentHandler ?: ctapAuthenticator.makeCredentialConsentHandler
    val getAssertionConsentHandler: GetAssertionConsentHandler = getAssertionConsentHandler ?: ctapAuthenticator.getAssertionConsentHandler
    val selectionHandler: SelectionHandler = selectionHandler ?: ctapAuthenticator.selectionHandler
    val credentialSelectionHandler: CredentialSelectionHandler = ctapAuthenticator.credentialSelectionHandler
    val winkHandler: WinkHandler = ctapAuthenticator.winkHandler
    val eventListeners: List<EventListener> = ctapAuthenticator.eventListeners.toList()
    val exceptionReporters: List<ExceptionReporter> = ctapAuthenticator.exceptionReporters.toList()

    val objectConverter = ctapAuthenticator.objectConverter
    val authenticatorDataConverter: AuthenticatorDataConverter = AuthenticatorDataConverter(ctapAuthenticator.objectConverter)
    val pinProtocols: List<PinProtocolVersion> = ctapAuthenticator.pinProtocols
        .sortedByDescending { it.value }

    val pinUvAuthManager: PinUvAuthManager = PinUvAuthManager(
        authenticatorPropertyStore,
        pinProtocols.map { version ->
            when (version) {
                PinProtocolVersion.VERSION_1 -> PinUvAuthProtocolV1()
                PinProtocolVersion.VERSION_2 -> PinUvAuthProtocolV2()
                else -> throw IllegalArgumentException("Unsupported PIN protocol version: $version")
            }
        }
    )

    val isClientPINReady: Boolean
        get() = authenticatorPropertyStore.loadClientPIN() != null

    // Authenticator characteristics
    val platform: AttachmentSetting = ctapAuthenticator.platform
    val residentKey: ResidentKeySetting = ctapAuthenticator.residentKey
    val clientPIN: ClientPINSetting = ctapAuthenticator.clientPIN
    val resetProtection: ResetProtectionSetting = ctapAuthenticator.resetProtection
    val credentialSelector: CredentialSelectorSetting = ctapAuthenticator.credentialSelector
    val userPresence: UserPresenceSetting = ctapAuthenticator.userPresence
    val userVerification: UserVerificationSetting = ctapAuthenticator.userVerification
    val alwaysUv: AlwaysUvSetting = ctapAuthenticator.alwaysUv
    val makeCredUvNotRqd: MakeCredUvNotRqdSetting = ctapAuthenticator.makeCredUvNotRqd

    // Authenticator properties
    val aaguid: AAGUID = ctapAuthenticator.aaguid


    var onGoingGetAssertionSession: GetAssertionSession? = null

    // The Job of the currently executing command, used by cancelOnGoingTransaction() to cancel it.
    // Set after mutex acquisition to avoid race conditions; cleared in finally.
    @Volatile
    private var activeTransaction: Job? = null

    @Volatile
    var isWaitingForUserPresence: Boolean = false
        private set

    suspend fun <T> withUserPresenceWait(block: suspend () -> T): T {
        isWaitingForUserPresence = true
        try {
            return block()
        } finally {
            isWaitingForUserPresence = false
        }
    }

    @Suppress("UNCHECKED_CAST")
    suspend fun <TC : AuthenticatorRequest, TR : AuthenticatorResponse?> invokeCommand(
        request: TC
    ): TR {
        return when (request) {
            is AuthenticatorMakeCredentialRequest -> makeCredential(request)
            is AuthenticatorGetAssertionRequest -> getAssertion(request)
            is AuthenticatorGetNextAssertionRequest -> getNextAssertion(request)
            is AuthenticatorGetInfoRequest -> getInfo(request)
            is AuthenticatorClientPINRequest -> clientPIN(request)
            is AuthenticatorResetRequest -> reset(request)
            is AuthenticatorSelectionRequest -> selection(request)
            is U2FRegistrationRequest -> u2fRegister(request)
            is U2FAuthenticationRequest -> u2fSign(request)
            else -> throw IllegalStateException("unknown command ${request::class.java}")
        } as TR
    }

    suspend fun makeCredential(authenticatorMakeCredentialCommand: AuthenticatorMakeCredentialRequest): AuthenticatorMakeCredentialResponse {
        return withTransaction {
            MakeCredentialExecution(this, authenticatorMakeCredentialCommand).execute()
        }
    }

    suspend fun getAssertion(authenticatorGetAssertionCommand: AuthenticatorGetAssertionRequest): AuthenticatorGetAssertionResponse {
        return withTransaction {
            GetAssertionExecution(this, authenticatorGetAssertionCommand).execute()
        }
    }

    @JvmOverloads
    suspend fun getNextAssertion(authenticatorGetNextAssertionCommand: AuthenticatorGetNextAssertionRequest = AuthenticatorGetNextAssertionRequest()): AuthenticatorGetNextAssertionResponse {
        return withTransaction {
            GetNextAssertionExecution(this, authenticatorGetNextAssertionCommand).execute()
        }
    }

    @JvmOverloads
    suspend fun getInfo(authenticatorGetInfoCommand: AuthenticatorGetInfoRequest = AuthenticatorGetInfoRequest()): AuthenticatorGetInfoResponse {
        return withTransaction {
            GetInfoExecution(this, authenticatorGetInfoCommand).execute()
        }
    }

    suspend fun clientPIN(authenticatorClientPINCommand: AuthenticatorClientPINRequest): AuthenticatorClientPINResponse {
        return withTransaction {
            ClientPINExecution(this, authenticatorClientPINCommand).execute()
        }
    }

    @JvmOverloads
    suspend fun selection(authenticatorSelectionRequest: AuthenticatorSelectionRequest = AuthenticatorSelectionRequest()): AuthenticatorSelectionResponse {
        return withTransaction {
            SelectionExecution(this, authenticatorSelectionRequest).execute()
        }
    }

    @JvmOverloads
    suspend fun reset(authenticatorResetCommand: AuthenticatorResetRequest = AuthenticatorResetRequest()): AuthenticatorResetResponse {
        return withTransaction {
            ResetExecution(this, authenticatorResetCommand).execute()
        }
    }

    @Suppress("MemberVisibilityCanBePrivate")
    suspend fun u2fRegister(u2fRegistrationRequest: U2FRegistrationRequest): U2FRegistrationResponse {
        return withTransaction {
            U2FRegisterExecution(this, u2fRegistrationRequest).execute()
        }
    }

    @Suppress("MemberVisibilityCanBePrivate")
    suspend fun u2fSign(u2fAuthenticationRequest: U2FAuthenticationRequest): U2FAuthenticationResponse {
        return withTransaction {
            U2FAuthenticationExecution(this, u2fAuthenticationRequest).execute()
        }
    }

    suspend fun wink() {
        withTransaction { winkHandler.onWink() }
    }

    // Serializes command execution with mutex and tracks the active Job for cancellation.
    // Uses async(LAZY) so that activeTransaction is set before the command starts.
    private suspend fun <T> withTransaction(block: suspend () -> T): T {
        return mutex.withLock {
            coroutineScope {
                val commandJob = async(start = CoroutineStart.LAZY) { block() }
                activeTransaction = commandJob
                commandJob.start()
                try {
                    commandJob.await()
                } finally {
                    activeTransaction = null
                }
            }
        }
    }

    suspend fun cancelOnGoingTransaction() {
        logger.debug("Cancel ongoing transaction requested")
        activeTransaction?.cancelAndJoin()
        onGoingGetAssertionSession = null
    }

    internal fun publishEvent(event: Event) {
        eventListeners.forEach { it.onEvent(event) }
    }

    internal fun reportException(exception: Exception) {
        exceptionReporters.forEach { it.onException(exception) }
    }

    @Deprecated("Lock is now handled at the HID transport layer", level = DeprecationLevel.WARNING)
    suspend fun lock(timeMillis: Long) {
    }

}

