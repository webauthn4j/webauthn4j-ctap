package com.unifidokey.core.service

import androidx.annotation.UiThread
import androidx.lifecycle.LiveData
import androidx.lifecycle.Transformations
import com.google.firebase.crashlytics.FirebaseCrashlytics
import com.unifidokey.core.adapter.UnifidoKeyAuthenticatorPropertyStore
import com.unifidokey.core.config.ConfigManager
import com.unifidokey.driver.persistence.converter.EventConverter
import com.unifidokey.driver.persistence.dao.EventDao
import com.webauthn4j.converter.util.ObjectConverter
import com.webauthn4j.ctap.authenticator.*
import com.webauthn4j.ctap.authenticator.attestation.AttestationStatementGenerator
import com.webauthn4j.ctap.authenticator.event.Event
import com.webauthn4j.ctap.authenticator.extension.HMACSecretExtensionProcessor
import com.webauthn4j.ctap.authenticator.settings.AttestationStatementFormatSetting
import com.webauthn4j.data.attestation.authenticator.AAGUID
import kotlinx.coroutines.runBlocking
import java.lang.Exception

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
    private val attestationStatementGenerators: Map<AttestationStatementFormatSetting, AttestationStatementGenerator>,
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
        configManager.clientPIN.liveData.observeForever { renewCtapAuthenticator() }
        configManager.resetProtection.liveData.observeForever { renewCtapAuthenticator() }
        configManager.credentialSelector.liveData.observeForever { renewCtapAuthenticator() }
        configManager.platform.liveData.observeForever { renewCtapAuthenticator() }
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
        val clientPINSetting = configManager.clientPIN.value
        val resetProtectionSetting = configManager.resetProtection.value
        val userPresenceSetting = configManager.userPresence.value
        val userVerificationSetting = configManager.userVerification.value
        val algorithms = configManager.algorithms.value
        val credentialSelectorSetting = configManager.credentialSelector.value
        val keyStorageSetting = configManager.keyStorage.value
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
        val attestationStatementGenerator =
            attestationStatementGenerators[attestationStatementFormatSetting]
                ?: throw IllegalArgumentException(
                    String.format(
                        "Attestation statement format:'%s' is not registered.",
                        attestationStatementFormatSetting
                    )
                )
        val extensionProcessors = listOf(HMACSecretExtensionProcessor())
        val ctapAuthenticator = CtapAuthenticator(
            attestationStatementGenerator,
            extensionProcessors,
            authenticatorPropertyStore,
            objectConverter,
            settings
        )
        userConsentHandler.let {
            if (it != null) {
                ctapAuthenticator.userConsentHandler = it
            }
        }
        credentialSelectionHandler.let {
            if (it != null) {
                ctapAuthenticator.credentialSelectionHandler = it
            }
        }
        ctapAuthenticator.registerEventListener(this::onEvent)
        ctapAuthenticator.registerExceptionReporter(this::onException)
        this@AuthenticatorService.ctapAuthenticator = ctapAuthenticator
    }

    private fun onEvent(event: Event) {
        val eventEntity = eventConverter.toEventEntity(event)
        eventDao.create(eventEntity)
    }

    private fun onException(exception: Exception){
        FirebaseCrashlytics.getInstance().recordException(exception)
    }
}
