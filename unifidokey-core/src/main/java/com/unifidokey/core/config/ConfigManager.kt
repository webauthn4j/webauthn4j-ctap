package com.unifidokey.core.config

import androidx.annotation.UiThread
import com.unifidokey.core.adapter.PersistenceAdaptor
import com.unifidokey.core.setting.KeyStorageSetting
import com.webauthn4j.ctap.authenticator.data.settings.AttestationStatementFormatSetting
import com.webauthn4j.ctap.authenticator.data.settings.AttestationTypeSetting
import com.webauthn4j.ctap.authenticator.data.settings.ResidentKeySetting
import com.webauthn4j.data.attestation.authenticator.AAGUID
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier
import java.security.SecureRandom

class ConfigManager(
    val persistenceAdaptor: PersistenceAdaptor,
    val nfcFeatureFlag: Boolean = true,
    val bleFeatureFlag: Boolean = true,
    val bthidFeatureFlag: Boolean = true
) {
    // modes
    val developerMode = DeveloperModeConfigProperty(this)
    val experimentalMode = ExperimentalModeConfigProperty(this)

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
    val biometricAuthentication = BiometricAuthenticationConfigProperty(this)
    val consentCaching = ConsentCachingConfigProperty(this)
    val resetProtection = ResetProtectionConfigProperty(this)
    val credentialSelector = CredentialSelectorConfigProperty(this)
    val keepScreenOn = KeepScreenOnConfigProperty(this)
    val allowedAppList = AllowedAppListConfigProperty(this)
    val attachment = PlatformConfigProperty(this)
    val clientPIN = ClientPINConfigProperty(this)
    val userVerification = UserVerificationConfigProperty(this)
    val userPresence = UserPresenceConfigProperty(this)
    val algorithms = AlgConfigProperty(this)
    val attestationType = AttestationTypeConfigProperty(this)
    val attestationStatementFormat = AttestationStatementFormatConfigProperty(this)
    val residentKey = ResidentKeyConfigProperty(this)
    val keyStorage = KeyStorageConfigProperty(this)

    val properties = listOf(
        developerMode,
        experimentalMode,
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
        biometricAuthentication,
        consentCaching,
        resetProtection,
        credentialSelector,
        keepScreenOn,
        allowedAppList,
        attachment,
        clientPIN,
        userVerification,
        userPresence,
        algorithms,
        attestationType,
        attestationStatementFormat,
        residentKey,
        keyStorage
    )

    val developerProperties = properties.filter { it.developerFeature }
    val experimentalProperties = properties.filter { it.experimentalFeature }
    private val resetTargetProperties = properties.filter { it.resetTarget }

    companion object {

        fun generateIV(): ByteArray {
            val value = ByteArray(16)
            SecureRandom().nextBytes(value)
            return value
        }
    }

    init {
        setupCorrelationRules()
    }

    @UiThread
    fun setup() {
    }

    fun reset() {
        resetTargetProperties.forEach { it.reset() }
    }


    @UiThread
    private fun setupCorrelationRules() {
        keyStorage.liveData.observeForever { value ->
            if (value != KeyStorageSetting.KEYSTORE && attestationStatementFormat.value == AttestationStatementFormatSetting.COMPOUND) {
                attestationStatementFormat.value = AttestationStatementFormatSetting.PACKED
            }
            if (value != KeyStorageSetting.KEYSTORE && attestationStatementFormat.value == AttestationStatementFormatSetting.ANDROID_KEY) {
                attestationStatementFormat.value = AttestationStatementFormatSetting.PACKED
            }
        }
        algorithms.liveData.observeForever { value ->
            if (value != setOf(COSEAlgorithmIdentifier.ES256) && attestationStatementFormat.value == AttestationStatementFormatSetting.FIDO_U2F) {
                attestationStatementFormat.value = AttestationStatementFormatSetting.PACKED
            }
        }
        attestationType.liveData.observeForever { value ->
            when (value) {
                AttestationTypeSetting.BASIC -> {
                    if (attestationStatementFormat.value == AttestationStatementFormatSetting.NONE) {
                        attestationStatementFormat.value = AttestationStatementFormatSetting.PACKED
                    }
                }
                AttestationTypeSetting.SELF -> {
                    if (attestationStatementFormat.value != AttestationStatementFormatSetting.PACKED && attestationStatementFormat.value != AttestationStatementFormatSetting.FIDO_U2F) {
                        attestationStatementFormat.value = AttestationStatementFormatSetting.PACKED
                    }
                }
                AttestationTypeSetting.NONE -> {
                    attestationStatementFormat.value = AttestationStatementFormatSetting.NONE
                }
                else -> { /*nop*/
                }
            }
        }
        attestationStatementFormat.liveData.observeForever { value ->
            when (value) {
                AttestationStatementFormatSetting.COMPOUND -> {
                    residentKey.value = ResidentKeySetting.ALWAYS
                    keyStorage.value = KeyStorageSetting.KEYSTORE
                    attestationType.value = AttestationTypeSetting.BASIC
                }
                AttestationStatementFormatSetting.ANDROID_KEY -> {
                    residentKey.value = ResidentKeySetting.ALWAYS
                    keyStorage.value = KeyStorageSetting.KEYSTORE
                    attestationType.value = AttestationTypeSetting.BASIC
                }
                AttestationStatementFormatSetting.ANDROID_SAFETYNET -> {
                    attestationType.value = AttestationTypeSetting.BASIC
                }
                AttestationStatementFormatSetting.PACKED -> {
                    if (attestationType.value == AttestationTypeSetting.NONE) {
                        attestationType.value = AttestationTypeSetting.SELF
                    }
                }
                AttestationStatementFormatSetting.FIDO_U2F -> {
                    aaguid.value = AAGUID.ZERO
                    algorithms.value = setOf(COSEAlgorithmIdentifier.ES256)
                    if (attestationType.value == AttestationTypeSetting.NONE) {
                        attestationType.value = AttestationTypeSetting.SELF
                    }
                }
                AttestationStatementFormatSetting.NONE -> {
                    attestationType.value = AttestationTypeSetting.NONE
                }
                else -> { /*nop*/
                }
            }
        }
        residentKey.liveData.observeForever { value: ResidentKeySetting ->
            if (value !== ResidentKeySetting.ALWAYS && attestationStatementFormat.value == AttestationStatementFormatSetting.COMPOUND) {
                attestationStatementFormat.value = AttestationStatementFormatSetting.PACKED
            }
            if (value !== ResidentKeySetting.ALWAYS && attestationStatementFormat.value == AttestationStatementFormatSetting.ANDROID_KEY) {
                attestationStatementFormat.value = AttestationStatementFormatSetting.PACKED
            }
        }
        biometricAuthentication.liveData.observeForever{ /*nop*/ } //necessary for .map method call
    }

}