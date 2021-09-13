package com.unifidokey.core.config

import androidx.annotation.UiThread
import com.unifidokey.core.adapter.PersistenceAdaptor
import com.unifidokey.core.setting.KeyStorageSetting
import com.webauthn4j.ctap.authenticator.settings.AttestationStatementFormatSetting
import com.webauthn4j.ctap.authenticator.settings.ConsentCachingSetting
import com.webauthn4j.ctap.authenticator.settings.ResidentKeySetting
import com.webauthn4j.data.attestation.authenticator.AAGUID
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier
import java.security.SecureRandom

class ConfigManager(
    val persistenceAdaptor: PersistenceAdaptor,
    val nfcFeatureFlag: Boolean = true,
    val bleFeatureFlag: Boolean = true,
    val bthidFeatureFlag: Boolean = true
) {

    // characteristics
    val aaguid = AAGUIDConfigProperty(this)
    val credentialSourceEncryptionIV = CredentialSourceEncryptionIVConfigProperty(this)
    val caCertificates = CACertificatesConfigProperty(this)

    // clientPIN
    val clientPINEnc = ClientPINEncConfigProperty(this)
    val pinRetries = PINRetriesConfigProperty(this)

    // counter
    val deviceWideCounter = DeviceWideCounterConfigProperty(this)

    // transports
    val isNFCTransportEnabled = NFCTransportEnabledConfigProperty(this)
    val isBLETransportEnabled = BLETransportEnabledConfigProperty(this)
    val isBTHIDTransportEnabled = BTHIDTransportEnabledConfigProperty(this)
    val bthidDeviceHistory = BTHIDDeviceHistoryConfigProperty(this)
    val isBTHIDBackgroundServiceModeEnabled = BTHIDBackgroundServiceModeEnabledConfigProperty(this)

    // settings
    val userConsent = UserConsentConfigProperty(this)
    val consentCaching = ConsentCachingConfigProperty(this)
    val resetProtection = ResetProtectionConfigProperty(this)
    val credentialSelector = CredentialSelectorConfigProperty(this)
    val keepScreenOn = KeepScreenOnConfigProperty(this)
    val platform = PlatformConfigProperty(this)
    val clientPIN = ClientPINConfigProperty(this)
    val userVerification = UserVerificationConfigProperty(this)
    val userPresence = UserPresenceConfigProperty(this)
    val algorithms = AlgConfigProperty(this)
    val attestationStatementFormat = AttestationStatementFormatConfigProperty(this)
    val residentKey = ResidentKeyConfigProperty(this)
    val keyStorage = KeyStorageConfigProperty(this)

    private val properties = listOf(
        aaguid,
        credentialSourceEncryptionIV,
        caCertificates,
        clientPINEnc,
        pinRetries,
        deviceWideCounter,
        isNFCTransportEnabled,
        isBLETransportEnabled,
        isBTHIDTransportEnabled,
        bthidDeviceHistory,
        isBTHIDBackgroundServiceModeEnabled,
        userConsent,
        consentCaching,
        resetProtection,
        credentialSelector,
        keepScreenOn,
        platform,
        clientPIN,
        userVerification,
        userPresence,
        algorithms,
        attestationStatementFormat,
        residentKey,
        keyStorage
    )

    companion object {
        // transports
        const val BTHID_PAIRING_PREF_KEY = "bthidPairing"
        fun generateIV(): ByteArray {
            val value = ByteArray(16)
            SecureRandom().nextBytes(value)
            return value
        }
    }

    init {
        properties.forEach { it.initialize() }
        setupCorrelationRules()
    }

    @UiThread
    fun setup() {
    }


    @UiThread
    private fun setupCorrelationRules() {
        keyStorage.liveData.observeForever { value ->
            if (value != KeyStorageSetting.KEYSTORE && attestationStatementFormat.value == AttestationStatementFormatSetting.ANDROID_KEY) {
                attestationStatementFormat.value = AttestationStatementFormatSetting.PACKED
            }
        }
        algorithms.liveData.observeForever{ value ->
            if(value != setOf(COSEAlgorithmIdentifier.ES256) && attestationStatementFormat.value == AttestationStatementFormatSetting.FIDO_U2F){
                attestationStatementFormat.value = AttestationStatementFormatSetting.PACKED
            }
        }
        attestationStatementFormat.liveData.observeForever { value ->
            when (value) {
                AttestationStatementFormatSetting.ANDROID_KEY -> {
                    residentKey.value = ResidentKeySetting.ALWAYS
                    keyStorage.value = KeyStorageSetting.KEYSTORE
                }
                AttestationStatementFormatSetting.FIDO_U2F -> {
                    aaguid.value = AAGUID.ZERO
                    algorithms.value = setOf(COSEAlgorithmIdentifier.ES256)
                }
                else -> { /*nop*/ }
            }
        }
        residentKey.liveData.observeForever { value: ResidentKeySetting ->
            if (value !== ResidentKeySetting.ALWAYS && attestationStatementFormat.value == AttestationStatementFormatSetting.ANDROID_KEY) {
                attestationStatementFormat.value = AttestationStatementFormatSetting.PACKED
            }
        }
    }

}