package com.webauthn4j.ctap.authenticator

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.dataformat.cbor.CBORFactory
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule
import com.fasterxml.jackson.module.kotlin.KotlinModule
import com.webauthn4j.converter.util.ObjectConverter
import com.webauthn4j.ctap.authenticator.attestation.AttestationStatementProvider
import com.webauthn4j.ctap.authenticator.attestation.FIDOU2FAttestationStatementProvider
import com.webauthn4j.ctap.authenticator.attestation.FIDOU2FBasicAttestationStatementProvider
import com.webauthn4j.ctap.authenticator.attestation.NoneAttestationStatementProvider
import com.webauthn4j.ctap.authenticator.data.credential.Credential
import com.webauthn4j.ctap.authenticator.data.settings.ClientPINSetting
import com.webauthn4j.ctap.authenticator.data.settings.CredentialSelectorSetting
import com.webauthn4j.ctap.authenticator.data.settings.AttachmentSetting
import com.webauthn4j.ctap.authenticator.data.settings.ResetProtectionSetting
import com.webauthn4j.ctap.authenticator.data.settings.ResidentKeySetting
import com.webauthn4j.ctap.authenticator.data.settings.UserPresenceSetting
import com.webauthn4j.ctap.authenticator.data.settings.UserVerificationSetting
import com.webauthn4j.ctap.authenticator.extension.ExtensionProcessor
import com.webauthn4j.ctap.authenticator.store.AuthenticatorPropertyStore
import com.webauthn4j.ctap.authenticator.store.InMemoryAuthenticatorPropertyStore
import com.webauthn4j.ctap.core.converter.jackson.CtapCBORModule
import com.webauthn4j.ctap.core.converter.jackson.PublicKeyCredentialSourceCBORModule
import com.webauthn4j.ctap.core.data.PinProtocolVersion
import com.webauthn4j.ctap.core.data.options.UserVerificationOption
import com.webauthn4j.data.AuthenticatorTransport
import com.webauthn4j.data.attestation.authenticator.AAGUID
import org.slf4j.LoggerFactory

class CtapAuthenticator(
    val objectConverter: ObjectConverter = createObjectConverter(),
    // Core logic delegates
    // These are final as it should not be updated on the fly for integrity. To update these, new instance should be created.
    var attestationStatementProvider: AttestationStatementProvider = NoneAttestationStatementProvider(),
    var fidoU2FBasicAttestationStatementGenerator: FIDOU2FAttestationStatementProvider = FIDOU2FBasicAttestationStatementProvider.createWithDemoAttestationKey(),
    transports: Set<AuthenticatorTransport> = setOf(),
    val extensionProcessors: List<ExtensionProcessor> = listOf(),
    // Handlers
    var authenticatorPropertyStore: AuthenticatorPropertyStore = InMemoryAuthenticatorPropertyStore(),
    var userVerificationHandler: UserVerificationHandler = object : UserVerificationHandler {
        override fun getUserVerificationOption(rpId: String?): UserVerificationOption = UserVerificationOption.READY

        override suspend fun onMakeCredentialConsentRequested(makeCredentialConsentRequest: MakeCredentialConsentRequest): Boolean {
            return true
        }

        override suspend fun onGetAssertionConsentRequested(getAssertionConsentRequest: GetAssertionConsentRequest): Boolean {
            return true
        }
    },
    var credentialSelectionHandler: CredentialSelectionHandler = DefaultCredentialSelectionHandler(),
    var winkHandler: WinkHandler = NoopWinkHandler()
) {

    companion object{
        @JvmField
        val AAGUID = AAGUID("33c1642b-b5e9-423d-9add-5a0119c2a8b8")
        const val VERSION_U2F_V2 = "U2F_V2"
        const val VERSION_FIDO_2_0 = "FIDO_2_0"
        const val VERSION_FIDO_2_1_PRE = "FIDO_2_1_PRE"

        @JvmField
        val VERSIONS = listOf(VERSION_U2F_V2, VERSION_FIDO_2_0)

        @JvmField
        val PIN_PROTOCOLS = listOf(PinProtocolVersion.VERSION_1)
        private fun createObjectConverter(): ObjectConverter {
            val jsonMapper = ObjectMapper()
            val cborMapper = ObjectMapper(CBORFactory())
            cborMapper.registerModule(CtapCBORModule())
            cborMapper.registerModule(PublicKeyCredentialSourceCBORModule())
            cborMapper.registerModule(JavaTimeModule())
            cborMapper.registerModule(KotlinModule.Builder().build())
            return ObjectConverter(jsonMapper, cborMapper)
        }
    }

    val transports: MutableSet<AuthenticatorTransport> = transports.toMutableSet()
    internal val eventListeners: MutableList<EventListener> = mutableListOf()
    internal val exceptionReporters: MutableList<ExceptionReporter> = mutableListOf()

    var aaguid: AAGUID = AAGUID

    var platform: AttachmentSetting = AttachmentSetting.CROSS_PLATFORM
    var residentKey: ResidentKeySetting = ResidentKeySetting.ALWAYS
    var clientPIN: ClientPINSetting = ClientPINSetting.ENABLED
    var resetProtection: ResetProtectionSetting = ResetProtectionSetting.DISABLED
    var userPresence: UserPresenceSetting = UserPresenceSetting.SUPPORTED
    var userVerification: UserVerificationSetting = UserVerificationSetting.READY
    var credentialSelector: CredentialSelectorSetting = CredentialSelectorSetting.AUTHENTICATOR

    fun createSession(
        userVerificationHandler: UserVerificationHandler = this.userVerificationHandler
    ) : CtapAuthenticatorSession{
        return CtapAuthenticatorSession(this, userVerificationHandler)
    }

    fun registerEventListener(eventListener: EventListener) {
        eventListeners.add(eventListener)
    }

    fun unregisterEventListener(eventListener: EventListener) {
        eventListeners.remove(eventListener)
    }

    fun registerExceptionReporter(exceptionReporter: ExceptionReporter) {
        exceptionReporters.add(exceptionReporter)
    }

    fun unregisterExceptionReporter(exceptionReporter: ExceptionReporter) {
        exceptionReporters.remove(exceptionReporter)
    }

    private class DefaultCredentialSelectionHandler : CredentialSelectionHandler {
        override suspend fun onSelect(list: List<Credential>): Credential {
            return list.first()
        }
    }

    private class NoopWinkHandler : WinkHandler {

        private val logger = LoggerFactory.getLogger(NoopWinkHandler::class.java)

        override suspend fun onWink() {
            logger.debug("wink requested")
        }

    }
}