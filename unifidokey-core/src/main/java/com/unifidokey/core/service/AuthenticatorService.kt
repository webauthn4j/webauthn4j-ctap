package com.unifidokey.core.service

import androidx.annotation.UiThread
import androidx.lifecycle.LiveData
import androidx.lifecycle.Transformations
import com.unifidokey.core.adapter.UnifidoKeyAuthenticatorPropertyStore
import com.unifidokey.core.config.ConfigManager
import com.unifidokey.driver.persistence.converter.EventConverter
import com.unifidokey.driver.persistence.dao.EventDao
import com.webauthn4j.converter.util.ObjectConverter
import com.webauthn4j.ctap.authenticator.*
import com.webauthn4j.ctap.authenticator.attestation.AttestationStatementProvider
import com.webauthn4j.ctap.authenticator.attestation.FIDOU2FAttestationStatementProvider
import com.webauthn4j.ctap.authenticator.data.event.Event
import com.webauthn4j.ctap.authenticator.extension.HMACSecretExtensionProcessor
import com.webauthn4j.ctap.authenticator.data.settings.AttestationStatementFormatSetting
import com.webauthn4j.ctap.authenticator.data.settings.AttestationTypeSetting
import com.webauthn4j.ctap.authenticator.data.settings.ConsentCachingSetting
import com.webauthn4j.data.attestation.authenticator.AAGUID
import kotlinx.coroutines.runBlocking

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
) : TransactionManager() {

    companion object {
        @JvmField
        val AAGUID = AAGUID("62b0f4c6-5a10-4eba-b094-b44529d77bb0")
    }

    private val eventConverter = EventConverter(objectConverter)

    var userConsentHandler: UserConsentHandler? = null
        set(value) {
            field = value
            runBlocking {
                renewCtapAuthenticator()
            }
        }
    var credentialSelectionHandler: CredentialSelectionHandler? = null
        set(value) {
            field = value
            runBlocking {
                renewCtapAuthenticator()
            }
        }

    val events: LiveData<List<Event>> = Transformations.map(eventDao.findAllLiveData()) {
        return@map it.map { item -> eventConverter.toEvent(item) }
    }

    init {
        configManager.setup()
        renewCtapAuthenticator()
        setupConfigChangeListeners()
    }

    @UiThread
    private fun setupConfigChangeListeners() {
        configManager.aaguid.liveData.observeForever { renewCtapAuthenticator() }
        configManager.caCertificates.liveData.observeForever { renewCtapAuthenticator() }
        configManager.isNFCTransportEnabled.liveData.observeForever { renewCtapAuthenticator() }
        configManager.isBTHIDTransportEnabled.liveData.observeForever { renewCtapAuthenticator() }
        configManager.isBLETransportEnabled.liveData.observeForever { renewCtapAuthenticator() }
        configManager.userConsent.liveData.observeForever { renewCtapAuthenticator() }
        configManager.consentCaching.liveData.observeForever{ renewCtapAuthenticator() }
        configManager.resetProtection.liveData.observeForever { renewCtapAuthenticator() }
        configManager.credentialSelector.liveData.observeForever { renewCtapAuthenticator() }
        configManager.platform.liveData.observeForever { renewCtapAuthenticator() }
        configManager.clientPIN.liveData.observeForever { renewCtapAuthenticator() }
        configManager.userVerification.liveData.observeForever { renewCtapAuthenticator() }
        configManager.userPresence.liveData.observeForever { renewCtapAuthenticator() }
        configManager.algorithms.liveData.observeForever { renewCtapAuthenticator() }
        configManager.attestationStatementFormat.liveData.observeForever { renewCtapAuthenticator() }
        configManager.residentKey.liveData.observeForever { renewCtapAuthenticator() }
        configManager.keyStorage.liveData.observeForever { renewCtapAuthenticator() }
    }

    @UiThread
    private fun renewCtapAuthenticator() {
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
        val settings = CtapAuthenticatorSettings(
            aaguid,
            platformSetting,
            residentKeySetting,
            clientPINSetting,
            resetProtectionSetting,
            userPresenceSetting,
            userVerificationSetting,
            credentialSelectorSetting
        )
        authenticatorPropertyStore.keyStorageSetting = keyStorageSetting
        authenticatorPropertyStore.algorithms = algorithms
        val attestationStatementProvider =
            attestationStatementProviders[Pair(attestationTypeSetting, attestationStatementFormatSetting)]
                ?: throw IllegalArgumentException(
                    String.format(
                        "Attestation type: '%s' format:'%s' is not registered.",
                        attestationTypeSetting,
                        attestationStatementFormatSetting
                    )
                )
        val fidoU2FAttestationStatementProvider = attestationStatementProviders[Pair(attestationTypeSetting, AttestationStatementFormatSetting.FIDO_U2F)] as FIDOU2FAttestationStatementProvider
        val extensionProcessors = listOf(HMACSecretExtensionProcessor())
        val ctapAuthenticator = CtapAuthenticator(
            attestationStatementProvider,
            fidoU2FAttestationStatementProvider,
            extensionProcessors,
            authenticatorPropertyStore,
            objectConverter,
            settings
        )
        userConsentHandler.let {
            if (it != null) {
                ctapAuthenticator.userConsentHandler = when (configManager.consentCaching.value) {
                    ConsentCachingSetting.ENABLED -> CachingUserConsentHandler(it)
                    else -> CachingUserConsentHandler(it)
                }
            }
        }
        credentialSelectionHandler.let {
            if (it != null) {
                ctapAuthenticator.credentialSelectionHandler = when(configManager.consentCaching.value){
                    ConsentCachingSetting.ENABLED -> CachingCredentialSelectionHandler(it)
                    else -> it
                }
            }
        }
        ctapAuthenticator.registerEventListener(this::onEvent)
        ctapAuthenticator.registerExceptionReporter(exceptionReporter)
        this@AuthenticatorService.ctapAuthenticator = ctapAuthenticator
    }

    private fun onEvent(event: Event) {
        val eventEntity = eventConverter.toEventEntity(event)
        eventDao.create(eventEntity)
    }

}
