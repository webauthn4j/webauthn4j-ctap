package com.unifidokey.app.handheld.presentation

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import com.unifidokey.app.UnifidoKeyComponent
import com.unifidokey.app.handheld.UnifidoKeyHandHeldApplication
import com.unifidokey.core.config.BTHIDDeviceHistoryEntry
import com.unifidokey.core.config.ConfigManager
import com.unifidokey.core.setting.KeepScreenOnSetting
import com.unifidokey.core.setting.KeyStorageSetting
import com.webauthn4j.ctap.authenticator.settings.*
import com.webauthn4j.data.attestation.authenticator.AAGUID
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier
import org.slf4j.LoggerFactory

class SettingsViewModel(application: Application) : AndroidViewModel(application) {
    private val logger = LoggerFactory.getLogger(SettingsViewModel::class.java)
    private val unifidoKeyComponent: UnifidoKeyComponent
    private val configManager: ConfigManager

    init {
        val unifidoKeyHandHeldApplication = application as UnifidoKeyHandHeldApplication
        unifidoKeyComponent = unifidoKeyHandHeldApplication.unifidoKeyComponent
        configManager = unifidoKeyComponent.configManager
    }

    fun setNFCEnabled(value: Boolean): Boolean {
        return try {
            configManager.isNFCTransportEnabled.value = value
            true
        } catch (e: RuntimeException) {
            logger.error("Unexpected exception is thrown", e)
            false
        }
    }

    fun setBLEEnabled(value: Boolean): Boolean {
        return try {
            configManager.isBLETransportEnabled.value = value
            true
        } catch (e: RuntimeException) {
            logger.error("Unexpected exception is thrown", e)
            false
        }
    }

    fun setBTHIDEnabled(value: Boolean): Boolean {
        return try {
            configManager.isBTHIDTransportEnabled.value = value
            true
        } catch (e: RuntimeException) {
            logger.error("Unexpected exception is thrown", e)
            false
        }
    }

    fun setBTHIDeviceHistory(value: List<BTHIDDeviceHistoryEntry>): Boolean {
        return try {
            configManager.bthidDeviceHistory.value = value
            true
        } catch (e: RuntimeException) {
            logger.error("Unexpected exception is thrown", e)
            false
        }
    }

    fun setUserVerificationSetting(userVerificationSetting: UserVerificationSetting): Boolean {
        return try {
            configManager.userVerification.value = userVerificationSetting
            true
        } catch (e: RuntimeException) {
            logger.error("Unexpected exception is thrown", e)
            false
        }
    }

    fun setUserPresenceSetting(userPresenceSetting: UserPresenceSetting): Boolean {
        return try {
            configManager.userPresence.value = userPresenceSetting
            true
        } catch (e: RuntimeException) {
            logger.error("Unexpected exception is thrown", e)
            false
        }
    }

    fun setClientPINSetting(clientPINSetting: ClientPINSetting): Boolean {
        return try {
            configManager.clientPIN.value = clientPINSetting
            true
        } catch (e: RuntimeException) {
            logger.error("Unexpected exception is thrown", e)
            false
        }
    }

    fun setResetProtectionSetting(resetProtectionSetting: ResetProtectionSetting): Boolean {
        return try {
            configManager.resetProtection.value = resetProtectionSetting
            true
        } catch (e: RuntimeException) {
            logger.error("Unexpected exception is thrown", e)
            false
        }
    }

    fun setConsentCachingSetting(consentCachingSetting: ConsentCachingSetting): Boolean {
        return try {
            configManager.consentCaching.value = consentCachingSetting
            true
        } catch (e: RuntimeException) {
            logger.error("Unexpected exception is thrown", e)
            false
        }
    }

    fun setCredentialSelectorSetting(credentialSelectorSetting: CredentialSelectorSetting): Boolean {
        return try {
            configManager.credentialSelector.value = credentialSelectorSetting
            true
        } catch (e: RuntimeException) {
            logger.error("Unexpected exception is thrown", e)
            false
        }
    }

    fun setKeepScreenOnSetting(keepScreenOnSetting: KeepScreenOnSetting): Boolean {
        return try {
            configManager.keepScreenOn.value = keepScreenOnSetting
            true
        } catch (e: RuntimeException) {
            logger.error("Unexpected exception is thrown", e)
            false
        }
    }

    fun setAaguid(aaguid: AAGUID): Boolean {
        return try {
            configManager.aaguid.value = aaguid
            true
        } catch (e: RuntimeException) {
            logger.error("Unexpected exception is thrown", e)
            false
        }
    }

    fun setPlatformSetting(platformSetting: PlatformSetting): Boolean {
        return try {
            configManager.platform.value = platformSetting
            true
        } catch (e: RuntimeException) {
            logger.error("Unexpected exception is thrown", e)
            false
        }
    }

    fun setAlgorithms(algorithms: Set<COSEAlgorithmIdentifier>): Boolean {
        return try {
            configManager.algorithms.value = algorithms
            true
        } catch (e: RuntimeException) {
            logger.error("Unexpected exception is thrown", e)
            false
        }
    }

    fun setAttestationStatementFormatSetting(identifier: AttestationStatementFormatSetting): Boolean {
        return try {
            configManager.attestationStatementFormat.value = identifier
            true
        } catch (e: RuntimeException) {
            logger.error("Unexpected exception is thrown", e)
            false
        }
    }

    fun setResidentKeySetting(residentKeySetting: ResidentKeySetting): Boolean {
        return try {
            configManager.residentKey.value = residentKeySetting
            true
        } catch (e: RuntimeException) {
            logger.error("Unexpected exception is thrown", e)
            false
        }
    }

    fun setKeyStorageSetting(credentialStorage: KeyStorageSetting): Boolean {
        return try {
            configManager.keyStorage.value = credentialStorage
            true
        } catch (e: RuntimeException) {
            logger.error("Unexpected exception is thrown", e)
            false
        }
    }



}