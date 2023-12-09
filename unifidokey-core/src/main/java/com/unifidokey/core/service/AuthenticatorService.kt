package com.unifidokey.core.service

import androidx.annotation.UiThread
import androidx.lifecycle.LiveData
import androidx.lifecycle.map
import com.unifidokey.core.adapter.UnifidoKeyAuthenticatorPropertyStore
import com.unifidokey.core.config.ConfigManager
import com.unifidokey.driver.persistence.converter.EventConverter
import com.unifidokey.driver.persistence.dao.EventDao
import com.webauthn4j.converter.util.ObjectConverter
import com.webauthn4j.ctap.authenticator.CachingCredentialSelectionHandler
import com.webauthn4j.ctap.authenticator.CachingGetAssertionConsentRequestHandler
import com.webauthn4j.ctap.authenticator.CachingMakeCredentialConsentRequestHandler
import com.webauthn4j.ctap.authenticator.CredentialSelectionHandler
import com.webauthn4j.ctap.authenticator.CtapAuthenticator
import com.webauthn4j.ctap.authenticator.ExceptionReporter
import com.webauthn4j.ctap.authenticator.GetAssertionConsentRequestHandler
import com.webauthn4j.ctap.authenticator.MakeCredentialConsentRequestHandler
import com.webauthn4j.ctap.authenticator.attestation.AttestationStatementProvider
import com.webauthn4j.ctap.authenticator.attestation.FIDOU2FAttestationStatementProvider
import com.webauthn4j.ctap.authenticator.data.event.Event
import com.webauthn4j.ctap.authenticator.data.settings.AttestationStatementFormatSetting
import com.webauthn4j.ctap.authenticator.data.settings.AttestationTypeSetting
import com.webauthn4j.ctap.authenticator.data.settings.ConsentCachingSetting
import com.webauthn4j.ctap.authenticator.extension.HMACSecretExtensionProcessor
import com.webauthn4j.ctap.authenticator.transport.nfc.NFCTransport
import com.webauthn4j.data.AuthenticatorTransport
import com.webauthn4j.data.attestation.authenticator.AAGUID

/**
 * Domain service for authenticator
 */
class AuthenticatorService(
    private val authenticatorPropertyStore: UnifidoKeyAuthenticatorPropertyStore,
    private val configManager: ConfigManager,
    val nfcService: NFCService,
    val bleService: BLEService,
    val bthidService: BTHIDService,
    private val eventDao: EventDao,
    private val attestationStatementProviders: Map<Pair<AttestationTypeSetting, AttestationStatementFormatSetting>, AttestationStatementProvider>,
    val exceptionReporter: ExceptionReporter,
    val objectConverter: ObjectConverter
) {

    companion object {
        @JvmField
        val AAGUID: AAGUID = com.webauthn4j.data.attestation.authenticator.AAGUID.ZERO //AAGUID("62b0f4c6-5a10-4eba-b094-b44529d77bb0")
    }

    private val eventConverter = EventConverter(objectConverter)

    val ctapAuthenticator: CtapAuthenticator
    val nfcTransport: NFCTransport

    init {
        ctapAuthenticator = createCtapAuthenticator()
        nfcTransport = NFCTransport(ctapAuthenticator)
        configManager.setup()
    }

    var makeCredentialConsentRequestHandler: MakeCredentialConsentRequestHandler = this.ctapAuthenticator.makeCredentialConsentRequestHandler
        set(value) {
            field = value
            configureCtapAuthenticatorMakeCredentialConsentRequestHandler()
        }
    var getAssertionConsentRequestHandler: GetAssertionConsentRequestHandler = this.ctapAuthenticator.getAssertionConsentRequestHandler
        set(value) {
            field = value
            configureCtapAuthenticatorGetAssertionConsentRequestHandler()
        }

    var credentialSelectionHandler: CredentialSelectionHandler = this.ctapAuthenticator.credentialSelectionHandler
        set(value) {
            field = value
            configureCtapAuthenticatorCredentialSelectionHandler()
        }

    val events: LiveData<List<Event>> = eventDao.findAllLiveData().map {
        return@map it.map { item -> eventConverter.toEvent(item) }
    }

    init {
        //setupConfigChangeListeners must be called after fields are initialized
        setupConfigChangeListeners()
    }

    private fun createCtapAuthenticator() : CtapAuthenticator {
        val aaguid = configManager.aaguid.value
        val platformSetting = configManager.platform.value
        val residentKeySetting = configManager.residentKey.value
        val resetProtectionSetting = configManager.resetProtection.value
        val clientPINSetting = configManager.clientPIN.value
        val userPresenceSetting = configManager.userPresence.value
        val userVerificationSetting = configManager.userVerification.value
        val algorithms = configManager.algorithms.value
        val credentialSelectorSetting = configManager.credentialSelector.value
        val keyStorageSetting = configManager.keyStorage.value
        val attestationTypeSetting = configManager.attestationType.value
        val attestationStatementFormatSetting = configManager.attestationStatementFormat.value
        authenticatorPropertyStore.keyStorageSetting = keyStorageSetting
        authenticatorPropertyStore.algorithms = algorithms
        val attestationStatementProvider =
            attestationStatementProviders[Pair(
                attestationTypeSetting,
                attestationStatementFormatSetting
            )]
                ?: throw IllegalArgumentException(
                    String.format(
                        "Attestation type: '%s' format:'%s' is not registered.",
                        attestationTypeSetting,
                        attestationStatementFormatSetting
                    )
                )
        val fidoU2FAttestationStatementProvider = attestationStatementProviders[Pair(
            attestationTypeSetting,
            AttestationStatementFormatSetting.FIDO_U2F
        )] as FIDOU2FAttestationStatementProvider
        val extensionProcessors = listOf(HMACSecretExtensionProcessor())
        val ctapAuthenticator = CtapAuthenticator(
            objectConverter,
            attestationStatementProvider,
            fidoU2FAttestationStatementProvider,
            setOf(AuthenticatorTransport.USB, AuthenticatorTransport.NFC, AuthenticatorTransport.BLE, AuthenticatorTransport.INTERNAL),
            extensionProcessors,
            authenticatorPropertyStore
        )
        ctapAuthenticator.aaguid = aaguid
        ctapAuthenticator.platform = platformSetting
        ctapAuthenticator.residentKey = residentKeySetting
        ctapAuthenticator.clientPIN = clientPINSetting
        ctapAuthenticator.resetProtection = resetProtectionSetting
        ctapAuthenticator.userPresence = userPresenceSetting
        ctapAuthenticator.userVerification = userVerificationSetting
        ctapAuthenticator.credentialSelector = credentialSelectorSetting

        ctapAuthenticator.registerEventListener(this::onEvent)
        ctapAuthenticator.registerExceptionReporter(exceptionReporter)
        return ctapAuthenticator
    }

    @UiThread
    private fun setupConfigChangeListeners() {
        configManager.aaguid.liveData.observeForever { ctapAuthenticator.aaguid = configManager.aaguid.value }
//        configManager.isNFCTransportEnabled.liveData.observeForever { ctapAuthenticator.isNFCTransportEnabled = configManager.aaguid.value }
//        configManager.isBTHIDTransportEnabled.liveData.observeForever { ctapAuthenticator.isBTHIDTransportEnabled = configManager.aaguid.value }
//        configManager.isBLETransportEnabled.liveData.observeForever { ctapAuthenticator.isBLETransportEnabled = configManager.aaguid.value }
        configManager.consentCaching.liveData.observeForever {
            configureCtapAuthenticatorMakeCredentialConsentRequestHandler()
            configureCtapAuthenticatorGetAssertionConsentRequestHandler()
        }
        configManager.resetProtection.liveData.observeForever { ctapAuthenticator.resetProtection = configManager.resetProtection.value }
        configManager.credentialSelector.liveData.observeForever { ctapAuthenticator.credentialSelector = configManager.credentialSelector.value }
        configManager.platform.liveData.observeForever { ctapAuthenticator.platform = configManager.platform.value }
        configManager.clientPIN.liveData.observeForever { ctapAuthenticator.clientPIN = configManager.clientPIN.value }
        configManager.userVerification.liveData.observeForever { ctapAuthenticator.userVerification = configManager.userVerification.value }
        configManager.userPresence.liveData.observeForever { ctapAuthenticator.userPresence = configManager.userPresence.value }
        configManager.algorithms.liveData.observeForever { ctapAuthenticator.authenticatorPropertyStore.algorithms = configManager.algorithms.value }
        configManager.keyStorage.liveData.observeForever { (ctapAuthenticator.authenticatorPropertyStore as UnifidoKeyAuthenticatorPropertyStore).keyStorageSetting = configManager.keyStorage.value }
        configManager.attestationType.liveData.observeForever {
            ctapAuthenticator.attestationStatementProvider = getAttestationStatementProvider(configManager.attestationType.value, configManager.attestationStatementFormat.value)
            ctapAuthenticator.fidoU2FBasicAttestationStatementGenerator = attestationStatementProviders[Pair(
                configManager.attestationType.value,
                AttestationStatementFormatSetting.FIDO_U2F
            )] as FIDOU2FAttestationStatementProvider
        }
        configManager.attestationStatementFormat.liveData.observeForever {
            ctapAuthenticator.attestationStatementProvider = getAttestationStatementProvider(configManager.attestationType.value, configManager.attestationStatementFormat.value)
            ctapAuthenticator.fidoU2FBasicAttestationStatementGenerator = attestationStatementProviders[Pair(
                configManager.attestationType.value,
                AttestationStatementFormatSetting.FIDO_U2F
            )] as FIDOU2FAttestationStatementProvider
        }
        configManager.residentKey.liveData.observeForever { ctapAuthenticator.residentKey = configManager.residentKey.value }
    }

    private fun configureCtapAuthenticatorMakeCredentialConsentRequestHandler(){
        ctapAuthenticator.makeCredentialConsentRequestHandler = when (configManager.consentCaching.value) {
            ConsentCachingSetting.ENABLED -> CachingMakeCredentialConsentRequestHandler(this.makeCredentialConsentRequestHandler)
            else -> this.makeCredentialConsentRequestHandler
        }
    }

    private fun configureCtapAuthenticatorGetAssertionConsentRequestHandler(){
        ctapAuthenticator.getAssertionConsentRequestHandler = when (configManager.consentCaching.value) {
            ConsentCachingSetting.ENABLED -> CachingGetAssertionConsentRequestHandler(this.getAssertionConsentRequestHandler)
            else -> this.getAssertionConsentRequestHandler
        }
    }

    private fun configureCtapAuthenticatorCredentialSelectionHandler() {
        ctapAuthenticator.credentialSelectionHandler = when (configManager.consentCaching.value) {
            ConsentCachingSetting.ENABLED -> CachingCredentialSelectionHandler(this.credentialSelectionHandler)
            else -> this.credentialSelectionHandler
        }
    }

    private fun getAttestationStatementProvider(type: AttestationTypeSetting, format: AttestationStatementFormatSetting) =
        (attestationStatementProviders[Pair(type, format)]
            ?: throw IllegalArgumentException(
                String.format(
                    "Attestation type: '%s' format:'%s' is not registered.",
                    type,
                    format
                )
            ))

    private fun onEvent(event: Event) {
        val eventEntity = eventConverter.toEventEntity(event)
        eventDao.create(eventEntity)
    }

}
