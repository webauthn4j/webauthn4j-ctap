package com.webauthn4j.ctap.authenticator

import com.webauthn4j.converter.AuthenticatorDataConverter
import com.webauthn4j.ctap.authenticator.attestation.AttestationStatementProvider
import com.webauthn4j.ctap.authenticator.attestation.FIDOU2FAttestationStatementProvider
import com.webauthn4j.ctap.authenticator.data.event.Event
import com.webauthn4j.ctap.authenticator.data.settings.*
import com.webauthn4j.ctap.authenticator.execution.ClientPINExecution
import com.webauthn4j.ctap.authenticator.execution.GetAssertionExecution
import com.webauthn4j.ctap.authenticator.execution.GetInfoExecution
import com.webauthn4j.ctap.authenticator.execution.GetNextAssertionExecution
import com.webauthn4j.ctap.authenticator.execution.MakeCredentialExecution
import com.webauthn4j.ctap.authenticator.execution.ResetExecution
import com.webauthn4j.ctap.authenticator.execution.U2FAuthenticationExecution
import com.webauthn4j.ctap.authenticator.execution.U2FRegisterExecution
import com.webauthn4j.ctap.authenticator.extension.ExtensionProcessor
import com.webauthn4j.ctap.authenticator.store.AuthenticatorPropertyStore
import com.webauthn4j.ctap.core.data.*
import com.webauthn4j.data.AuthenticatorTransport
import com.webauthn4j.data.attestation.authenticator.AAGUID
import kotlinx.coroutines.delay
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.slf4j.LoggerFactory

/**
 * Ctap Authenticator
 */
class CtapAuthenticatorSession internal constructor(
    ctapAuthenticator: CtapAuthenticator
) {

    private val logger = LoggerFactory.getLogger(CtapAuthenticatorSession::class.java)

    private val mutex = Mutex()

    // Core logic delegates
    val attestationStatementProvider: AttestationStatementProvider = ctapAuthenticator.attestationStatementProvider
    val fidoU2FBasicAttestationStatementGenerator: FIDOU2FAttestationStatementProvider = ctapAuthenticator.fidoU2FBasicAttestationStatementGenerator
    val transports: Set<AuthenticatorTransport> = ctapAuthenticator.transports
    val extensionProcessors: List<ExtensionProcessor> = ctapAuthenticator.extensionProcessors
    val authenticatorPropertyStore: AuthenticatorPropertyStore = ctapAuthenticator.authenticatorPropertyStore
    val makeCredentialConsentRequestHandler: MakeCredentialConsentRequestHandler = ctapAuthenticator.makeCredentialConsentRequestHandler
    val getAssertionConsentRequestHandler: GetAssertionConsentRequestHandler = ctapAuthenticator.getAssertionConsentRequestHandler
    val credentialSelectionHandler: CredentialSelectionHandler = ctapAuthenticator.credentialSelectionHandler
    val winkHandler: WinkHandler = ctapAuthenticator.winkHandler
    val eventListeners: List<EventListener> = ctapAuthenticator.eventListeners.toList()
    val exceptionReporters: List<ExceptionReporter> = ctapAuthenticator.exceptionReporters.toList()

    val objectConverter = ctapAuthenticator.objectConverter
    val authenticatorDataConverter: AuthenticatorDataConverter = AuthenticatorDataConverter(ctapAuthenticator.objectConverter)
    val clientPINService: ClientPINService = ClientPINService(authenticatorPropertyStore)

    // Authenticator characteristics
    val platform: PlatformSetting = ctapAuthenticator.platform
    val residentKey: ResidentKeySetting = ctapAuthenticator.residentKey
    val clientPIN: ClientPINSetting = ctapAuthenticator.clientPIN
    val resetProtection: ResetProtectionSetting = ctapAuthenticator.resetProtection
    val credentialSelector: CredentialSelectorSetting = ctapAuthenticator.credentialSelector
    val userPresence: UserPresenceSetting = ctapAuthenticator.userPresence
    val userVerification: UserVerificationSetting = ctapAuthenticator.userVerification

    // Authenticator properties
    val aaguid: AAGUID = ctapAuthenticator.aaguid


    var onGoingGetAssertionSession: GetAssertionSession? = null

    suspend fun <TC : AuthenticatorRequest, TR : AuthenticatorResponse?> invokeCommand(request: TC): TR {
        val response = when (request) {
            is AuthenticatorMakeCredentialRequest -> makeCredential(request)
            is AuthenticatorGetAssertionRequest -> getAssertion(request)
            is AuthenticatorGetNextAssertionRequest -> getNextAssertion(request)
            is AuthenticatorGetInfoRequest -> getInfo(request)
            is AuthenticatorClientPINRequest -> clientPIN(request)
            is AuthenticatorResetRequest -> reset(request)
            is U2FRegistrationRequest -> u2fRegister(request)
            is U2FAuthenticationRequest -> u2fSign(request)
            else -> throw IllegalStateException(
                String.format(
                    "unknown command %s is invoked.",
                    request::class.java.toString()
                )
            )
        }
        @Suppress("UNCHECKED_CAST")
        return response as TR
    }

    suspend fun makeCredential(authenticatorMakeCredentialCommand: AuthenticatorMakeCredentialRequest): AuthenticatorMakeCredentialResponse {
        mutex.withLock {
            return MakeCredentialExecution(this, authenticatorMakeCredentialCommand).execute()
        }
    }

    suspend fun getAssertion(authenticatorGetAssertionCommand: AuthenticatorGetAssertionRequest): AuthenticatorGetAssertionResponse {
        mutex.withLock {
            return GetAssertionExecution(this, authenticatorGetAssertionCommand).execute()
        }
    }

    @JvmOverloads
    suspend fun getNextAssertion(authenticatorGetNextAssertionCommand: AuthenticatorGetNextAssertionRequest = AuthenticatorGetNextAssertionRequest()): AuthenticatorGetNextAssertionResponse {
        mutex.withLock {
            return GetNextAssertionExecution(this, authenticatorGetNextAssertionCommand).execute()
        }
    }

    @JvmOverloads
    suspend fun getInfo(authenticatorGetInfoCommand: AuthenticatorGetInfoRequest = AuthenticatorGetInfoRequest()): AuthenticatorGetInfoResponse {
        mutex.withLock {
            return GetInfoExecution(this, authenticatorGetInfoCommand).execute()
        }
    }

    suspend fun clientPIN(authenticatorClientPINCommand: AuthenticatorClientPINRequest): AuthenticatorClientPINResponse {
        mutex.withLock {
            return ClientPINExecution(this, authenticatorClientPINCommand).execute()
        }
    }

    @JvmOverloads
    suspend fun reset(authenticatorResetCommand: AuthenticatorResetRequest = AuthenticatorResetRequest()): AuthenticatorResetResponse {
        mutex.withLock {
            return ResetExecution(this, authenticatorResetCommand).execute()
        }
    }

    @Suppress("MemberVisibilityCanBePrivate")
    suspend fun u2fRegister(u2fRegistrationRequest: U2FRegistrationRequest): U2FRegistrationResponse {
        mutex.withLock {
            return U2FRegisterExecution(this, u2fRegistrationRequest).execute()
        }
    }

    @Suppress("MemberVisibilityCanBePrivate")
    suspend fun u2fSign(u2fAuthenticationRequest: U2FAuthenticationRequest): U2FAuthenticationResponse {
        mutex.withLock {
            return U2FAuthenticationExecution(this, u2fAuthenticationRequest).execute()
        }
    }

    suspend fun wink() {
        mutex.withLock {
            winkHandler.onWink()
        }
    }

    fun cancelOnGoingTransaction() {
        TODO()
//        mutex.withLock {
//            transaction?.cancel()
//        }
    }

    internal fun publishEvent(event: Event) {
        eventListeners.forEach { it.onEvent(event) }
    }

    internal fun reportException(exception: Exception) {
        exceptionReporters.forEach { it.onException(exception) }
    }

    suspend fun lock(timeMillis: Long) {
        mutex.withLock {
            delay(timeMillis)
        }
    }

}

