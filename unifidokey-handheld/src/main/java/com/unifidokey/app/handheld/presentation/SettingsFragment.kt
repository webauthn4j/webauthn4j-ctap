package com.unifidokey.app.handheld.presentation

import android.content.SharedPreferences
import android.content.SharedPreferences.OnSharedPreferenceChangeListener
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Toast
import androidx.preference.ListPreference
import androidx.preference.Preference
import androidx.preference.PreferenceFragmentCompat
import androidx.preference.SwitchPreference
import androidx.preference.SwitchPreferenceCompat
import com.unifidokey.R
import com.unifidokey.app.UnifidoKeyComponent
import com.unifidokey.app.handheld.UnifidoKeyHandHeldApplication
import com.unifidokey.app.handheld.presentation.util.BluetoothPairingUtil
import com.unifidokey.app.handheld.presentation.util.ConfigurationsResetConfirmationDialogUtil
import com.unifidokey.core.config.*
import com.unifidokey.core.service.BLEService
import com.unifidokey.core.service.BLEStatus
import com.unifidokey.core.service.BTHIDService
import com.unifidokey.core.service.NFCService
import com.unifidokey.core.setting.AllowedAppListSetting
import com.unifidokey.core.setting.BiometricAuthenticationSetting
import com.unifidokey.core.setting.KeepScreenOnSetting
import com.unifidokey.core.setting.KeyStorageSetting
import com.unifidokey.core.setting.UserConsentSetting
import com.webauthn4j.ctap.authenticator.data.settings.*
import com.webauthn4j.ctap.authenticator.data.settings.ResidentKeySetting.Companion.create
import com.webauthn4j.data.attestation.authenticator.AAGUID
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier
import com.webauthn4j.util.AssertUtil
import org.slf4j.LoggerFactory

@Suppress("UNCHECKED_CAST")
class SettingsFragment internal constructor(
    settingsActivity: SettingsActivity,
    viewModel: SettingsViewModel
) : PreferenceFragmentCompat(), OnSharedPreferenceChangeListener {
    private val logger = LoggerFactory.getLogger(SettingsFragment::class.java)
    private val settingsActivity: SettingsActivity
    private val viewModel: SettingsViewModel
    private val configManager: ConfigManager
    private val nfcService: NFCService
    private val bleService: BLEService
    private val bthidService: BTHIDService

    init {
        AssertUtil.notNull(settingsActivity, "settingsActivity must not be null")
        AssertUtil.notNull(viewModel, "viewModel must not be null")
        this.settingsActivity = settingsActivity
        this.viewModel = viewModel

        val unifidoKeyHandHeldApplication =
            settingsActivity.application as UnifidoKeyHandHeldApplication
        val unifidoKeyComponent: UnifidoKeyComponent =
            unifidoKeyHandHeldApplication.unifidoKeyComponent
        configManager = unifidoKeyComponent.configManager
        nfcService = unifidoKeyComponent.nfcService
        bleService = unifidoKeyComponent.bleService
        bthidService = unifidoKeyComponent.bthidService
    }

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        configManager.properties.map {
            findPreference<Preference>(it.key)?.isVisible = it.enabled
        }
        this.onDeveloperModeChanged(configManager.developerMode.value)
        this.onExperimentalModeChanged(configManager.experimentalMode.value)
        configManager.developerMode.liveData.observe(this.viewLifecycleOwner, this@SettingsFragment::onDeveloperModeChanged)
        configManager.experimentalMode.liveData.observe(this.viewLifecycleOwner, this@SettingsFragment::onExperimentalModeChanged)
        return super.onCreateView(inflater, container, savedInstanceState)
    }

    override fun onResume() {
        super.onResume()
        setupNFCAdapterEnabledListener()
        setupBLEAdapterEnabledListener()
        bleService.bleStatus.observe(
            viewLifecycleOwner
        ) { bleStatus: BLEStatus -> onBLEStatusChanged(bleStatus) }
    }

    override fun onPause() {
        super.onPause()
        bleService.bleStatus.removeObserver { bleStatus: BLEStatus -> onBLEStatusChanged(bleStatus) }
        tearDownBLEAdapterEnabledListener()
        tearDownNFCEnabledListener()
    }

    override fun onCreatePreferences(savedInstanceState: Bundle?, rootKey: String?) {
        configurePreferences(rootKey)
    }

    override fun onSharedPreferenceChanged(sharedPreferences: SharedPreferences?, key: String?) {
        if(key == null){
            return
        }
        // Update the value index of ListPreference to reflect the change to the user interface
        when (val preference = findPreference<Preference>(key)) {
            is ListPreference -> {
                val newValue = sharedPreferences?.getString(key, null)
                preference.setValueIndex(preference.findIndexOfValue(newValue))
            }
            is SwitchPreferenceCompat -> {
                val newValue = sharedPreferences?.getBoolean(key, false)
                newValue?.let {
                    preference.isChecked = newValue
                }
            }
        }

    }

    private fun configurePreferences(rootKey: String?) {
        setPreferencesFromResource(R.xml.root_preferences, rootKey)
        preferenceScreen.sharedPreferences!!.registerOnSharedPreferenceChangeListener(this)
        findPreference<Preference>(NFCTransportEnabledConfigProperty.KEY)!!.let {
            it.summaryProvider = NFCPreferenceSummaryProvider()
            it.onPreferenceChangeListener =
                Preference.OnPreferenceChangeListener { _: Preference?, newValue: Any ->
                    try {
                        val result = viewModel.setNFCEnabled(newValue as Boolean)
                        if (!result) {
                            Toast.makeText(
                                settingsActivity,
                                "NFC is not available on this smart phone.",
                                Toast.LENGTH_SHORT
                            ).show()
                        }
                        return@OnPreferenceChangeListener result
                    } catch (e: RuntimeException) {
                        logger.error("Unexpected exception is thrown", e)
                        Toast.makeText(
                            settingsActivity,
                            "Unexpected error has occurred.",
                            Toast.LENGTH_SHORT
                        ).show()
                        return@OnPreferenceChangeListener false
                    }
                }
        }
        findPreference<Preference>(BLETransportEnabledConfigProperty.KEY)!!.let {
            it.summaryProvider = BLEPreferenceSummaryProvider()
            it.onPreferenceChangeListener =
                Preference.OnPreferenceChangeListener { _: Preference?, newValue: Any ->
                    try {
                        val result = viewModel.setBLEEnabled(newValue as Boolean)
                        if (!result) {
                            Toast.makeText(
                                settingsActivity,
                                "BLE is not available on this smart phone.",
                                Toast.LENGTH_SHORT
                            ).show()
                        }
                        return@OnPreferenceChangeListener result
                    } catch (e: RuntimeException) {
                        logger.error("Unexpected exception is thrown", e)
                        Toast.makeText(
                            settingsActivity,
                            "Unexpected error has occurred.",
                            Toast.LENGTH_SHORT
                        ).show()
                        return@OnPreferenceChangeListener false
                    }
                }
        }
        findPreference<Preference>(BTHIDTransportEnabledConfigProperty.KEY)!!.let {
            it.summaryProvider = BTHIDPreferenceSummaryProvider()
            it.onPreferenceChangeListener =
                Preference.OnPreferenceChangeListener { _: Preference?, newValue: Any ->
                    try {
                        val result = viewModel.setBTHIDEnabled(newValue as Boolean)
                        if (!result) {
                            Toast.makeText(
                                settingsActivity,
                                "BLE is not available on this smart phone.",
                                Toast.LENGTH_SHORT
                            ).show()
                        }
                        return@OnPreferenceChangeListener result
                    } catch (e: RuntimeException) {
                        logger.error("Unexpected exception is thrown", e)
                        Toast.makeText(
                            settingsActivity,
                            "Unexpected error has occurred.",
                            Toast.LENGTH_SHORT
                        ).show()
                        return@OnPreferenceChangeListener false
                    }
                }
        }
        findPreference<Preference>(BTHID_PAIRING_KEY)!!.let {
            it.onPreferenceClickListener = Preference.OnPreferenceClickListener {
                BluetoothPairingUtil.startPairing(this.requireContext())
                return@OnPreferenceClickListener true
            }
            it.isVisible = configManager.bthidFeatureFlag
        }
        findPreference<Preference>(UserConsentConfigProperty.KEY)!!.onPreferenceChangeListener =
            Preference.OnPreferenceChangeListener { _: Preference?, newValue: Any? ->
                try {
                    val userConsentSetting = UserConsentSetting.create((newValue as String))
                    return@OnPreferenceChangeListener viewModel.setUserConsentSetting(userConsentSetting)
                } catch (e: RuntimeException) {
                    logger.error("Unexpected exception is thrown", e)
                    Toast.makeText(
                        settingsActivity,
                        "Unexpected error has occurred.",
                        Toast.LENGTH_SHORT
                    ).show()
                    return@OnPreferenceChangeListener false
                }
            }
        findPreference<Preference>(BiometricAuthenticationConfigProperty.KEY)!!.onPreferenceChangeListener =
            Preference.OnPreferenceChangeListener { _: Preference?, newValue: Any? ->
                try {
                    val biometricAuthenticationSetting = BiometricAuthenticationSetting.create((newValue as Boolean))
                    return@OnPreferenceChangeListener viewModel.setBiometricAuthenticationSetting(biometricAuthenticationSetting)
                } catch (e: RuntimeException) {
                    logger.error("Unexpected exception is thrown", e)
                    Toast.makeText(
                        settingsActivity,
                        "Unexpected error has occurred.",
                        Toast.LENGTH_SHORT
                    ).show()
                    return@OnPreferenceChangeListener false
                }
            }
        findPreference<Preference>(ClientPINConfigProperty.KEY)!!.onPreferenceChangeListener =
            Preference.OnPreferenceChangeListener { _: Preference?, newValue: Any? ->
                try {
                    val clientPINSetting = ClientPINSetting.create((newValue as String))
                    return@OnPreferenceChangeListener viewModel.setClientPINSetting(clientPINSetting)
                } catch (e: RuntimeException) {
                    logger.error("Unexpected exception is thrown", e)
                    Toast.makeText(
                        settingsActivity,
                        "Unexpected error has occurred.",
                        Toast.LENGTH_SHORT
                    ).show()
                    return@OnPreferenceChangeListener false
                }
            }
        findPreference<Preference>(ConsentCachingConfigProperty.KEY)!!.onPreferenceChangeListener =
            Preference.OnPreferenceChangeListener { _: Preference?, newValue: Any? ->
                try {
                    val consentCachingSetting = ConsentCachingSetting.create((newValue as Boolean))
                    return@OnPreferenceChangeListener viewModel.setConsentCachingSetting(consentCachingSetting)
                } catch (e: RuntimeException) {
                    logger.error("Unexpected exception is thrown", e)
                    Toast.makeText(
                        settingsActivity,
                        "Unexpected error has occurred.",
                        Toast.LENGTH_SHORT
                    ).show()
                    return@OnPreferenceChangeListener false
                }
            }
        findPreference<Preference>(ResetProtectionConfigProperty.KEY)!!.onPreferenceChangeListener =
            Preference.OnPreferenceChangeListener { _: Preference?, newValue: Any ->
                try {
                    val resetProtectionSetting = ResetProtectionSetting.create(newValue as Boolean)
                    return@OnPreferenceChangeListener viewModel.setResetProtectionSetting(
                        resetProtectionSetting
                    )
                } catch (e: RuntimeException) {
                    logger.error("Unexpected exception is thrown", e)
                    Toast.makeText(
                        settingsActivity,
                        "Unexpected error has occurred.",
                        Toast.LENGTH_SHORT
                    ).show()
                    return@OnPreferenceChangeListener false
                }
            }
        findPreference<Preference>(CredentialSelectorConfigProperty.KEY)!!.onPreferenceChangeListener =
            Preference.OnPreferenceChangeListener { _: Preference?, newValue: Any? ->
                try {
                    val credentialSelectorSetting =
                        CredentialSelectorSetting.create((newValue as String))
                    return@OnPreferenceChangeListener viewModel.setCredentialSelectorSetting(
                        credentialSelectorSetting
                    )
                } catch (e: RuntimeException) {
                    logger.error("Unexpected exception is thrown", e)
                    Toast.makeText(
                        settingsActivity,
                        "Unexpected error has occurred.",
                        Toast.LENGTH_SHORT
                    ).show()
                    return@OnPreferenceChangeListener false
                }
            }
        findPreference<Preference>(KeepScreenOnConfigProperty.KEY)!!.onPreferenceChangeListener =
            Preference.OnPreferenceChangeListener { _: Preference?, newValue: Any ->
                try {
                    val keepScreenOnSetting = KeepScreenOnSetting.create(newValue as Boolean)
                    return@OnPreferenceChangeListener viewModel.setKeepScreenOnSetting(
                        keepScreenOnSetting
                    )
                } catch (e: RuntimeException) {
                    logger.error("Unexpected exception is thrown", e)
                    Toast.makeText(
                        settingsActivity,
                        "Unexpected error has occurred.",
                        Toast.LENGTH_SHORT
                    ).show()
                    return@OnPreferenceChangeListener false
                }
            }
        findPreference<Preference>(AllowedAppListConfigProperty.KEY)!!.onPreferenceChangeListener =
            Preference.OnPreferenceChangeListener { _: Preference?, newValue: Any ->
                try {
                    val allowedAppListSetting = AllowedAppListSetting.create(newValue as String)
                    return@OnPreferenceChangeListener viewModel.setAllowedAppList(
                        allowedAppListSetting
                    )
                } catch (e: RuntimeException) {
                    logger.error("Unexpected exception is thrown", e)
                    Toast.makeText(
                        settingsActivity,
                        "Unexpected error has occurred.",
                        Toast.LENGTH_SHORT
                    ).show()
                    return@OnPreferenceChangeListener false
                }
            }
        findPreference<Preference>(AAGUIDConfigProperty.KEY)!!.onPreferenceChangeListener =
            Preference.OnPreferenceChangeListener { _: Preference?, newValue: Any? ->
                try {
                    val aaguid: AAGUID = try {
                        AAGUID(newValue as String?)
                    } catch (e: IllegalArgumentException) {
                        logger.warn("Invalid AAGUID format", e)
                        Toast.makeText(
                            settingsActivity,
                            "Invalid AAGUID format.",
                            Toast.LENGTH_SHORT
                        ).show()
                        return@OnPreferenceChangeListener false
                    }
                    return@OnPreferenceChangeListener viewModel.setAaguid(aaguid)
                } catch (e: RuntimeException) {
                    logger.error("Unexpected exception is thrown", e)
                    Toast.makeText(
                        settingsActivity,
                        "Unexpected error has occurred.",
                        Toast.LENGTH_SHORT
                    ).show()
                    return@OnPreferenceChangeListener false
                }
            }
        findPreference<Preference>(PlatformConfigProperty.KEY)!!.onPreferenceChangeListener =
            Preference.OnPreferenceChangeListener { _: Preference?, newValue: Any? ->
                try {
                    val attachmentSetting = AttachmentSetting.create((newValue as String?)!!)
                    return@OnPreferenceChangeListener viewModel.setPlatformSetting(attachmentSetting)
                } catch (e: RuntimeException) {
                    logger.error("Unexpected exception is thrown", e)
                    Toast.makeText(
                        settingsActivity,
                        "Unexpected error has occurred.",
                        Toast.LENGTH_SHORT
                    ).show()
                    return@OnPreferenceChangeListener false
                }
            }
        findPreference<Preference>(UserVerificationConfigProperty.KEY)!!.onPreferenceChangeListener =
            Preference.OnPreferenceChangeListener { _: Preference?, newValue: Any? ->
                try {
                    val userVerificationSetting =
                        UserVerificationSetting.create((newValue as String?)!!)
                    return@OnPreferenceChangeListener viewModel.setUserVerificationSetting(
                        userVerificationSetting
                    )
                } catch (e: RuntimeException) {
                    logger.error("Unexpected exception is thrown", e)
                    Toast.makeText(
                        settingsActivity,
                        "Unexpected error has occurred.",
                        Toast.LENGTH_SHORT
                    ).show()
                    return@OnPreferenceChangeListener false
                }
            }
        findPreference<Preference>(UserPresenceConfigProperty.KEY)!!.onPreferenceChangeListener =
            Preference.OnPreferenceChangeListener { _: Preference?, newValue: Any? ->
                try {
                    val userPresenceSetting = UserPresenceSetting.create((newValue as String?)!!)
                    return@OnPreferenceChangeListener viewModel.setUserPresenceSetting(
                        userPresenceSetting
                    )
                } catch (e: RuntimeException) {
                    logger.error("Unexpected exception is thrown", e)
                    Toast.makeText(
                        settingsActivity,
                        "Unexpected error has occurred.",
                        Toast.LENGTH_SHORT
                    ).show()
                    return@OnPreferenceChangeListener false
                }
            }
        findPreference<Preference>(AlgConfigProperty.KEY)!!.summaryProvider =
            AlgPreferenceSummaryProvider()
        findPreference<Preference>(AlgConfigProperty.KEY)!!.onPreferenceChangeListener =
            Preference.OnPreferenceChangeListener { _: Preference?, newValue: Any ->
                try {
                    val values = newValue as Set<String>
                    val algorithms =
                        values.map { item: String -> COSEAlgorithmIdentifier.create(item.toLong()) }
                            .toHashSet()
                    return@OnPreferenceChangeListener viewModel.setAlgorithms(algorithms)
                } catch (e: RuntimeException) {
                    logger.error("Unexpected exception is thrown", e)
                    Toast.makeText(
                        settingsActivity,
                        "Unexpected error has occurred.",
                        Toast.LENGTH_SHORT
                    ).show()
                    return@OnPreferenceChangeListener false
                }
            }
        findPreference<Preference>(AttestationTypeConfigProperty.KEY)!!.onPreferenceChangeListener =
            Preference.OnPreferenceChangeListener { _: Preference?, newValue: Any? ->
                try {
                    val attestationType = AttestationTypeSetting.create((newValue as String))
                    return@OnPreferenceChangeListener viewModel.setAttestationTypeSetting(
                        attestationType
                    )
                } catch (e: RuntimeException) {
                    logger.error("Unexpected exception is thrown", e)
                    Toast.makeText(
                        settingsActivity,
                        "Unexpected error has occurred.",
                        Toast.LENGTH_SHORT
                    ).show()
                    return@OnPreferenceChangeListener false
                }
            }
        findPreference<Preference>(AttestationStatementFormatConfigProperty.KEY)!!.onPreferenceChangeListener =
            Preference.OnPreferenceChangeListener { _: Preference?, newValue: Any? ->
                try {
                    val attestationStatementFormant = AttestationStatementFormatSetting.create((newValue as String))
                    return@OnPreferenceChangeListener viewModel.setAttestationStatementFormatSetting(
                        attestationStatementFormant
                    )
                } catch (e: RuntimeException) {
                    logger.error("Unexpected exception is thrown", e)
                    Toast.makeText(
                        settingsActivity,
                        "Unexpected error has occurred.",
                        Toast.LENGTH_SHORT
                    ).show()
                    return@OnPreferenceChangeListener false
                }
            }
        findPreference<Preference>(ResidentKeyConfigProperty.KEY)!!.onPreferenceChangeListener =
            Preference.OnPreferenceChangeListener { _: Preference?, newValue: Any? ->
                try {
                    val residentKeySetting = create(newValue as String)
                    return@OnPreferenceChangeListener viewModel.setResidentKeySetting(
                        residentKeySetting
                    )
                } catch (e: RuntimeException) {
                    logger.error("Unexpected exception is thrown", e)
                    Toast.makeText(
                        settingsActivity,
                        "Unexpected error has occurred.",
                        Toast.LENGTH_SHORT
                    ).show()
                    return@OnPreferenceChangeListener false
                }
            }
        findPreference<Preference>(KeyStorageConfigProperty.KEY)!!.onPreferenceChangeListener =
            Preference.OnPreferenceChangeListener { _: Preference?, newValue: Any? ->
                try {
                    val credentialStorage = KeyStorageSetting.create((newValue as String))
                    return@OnPreferenceChangeListener viewModel.setKeyStorageSetting(
                        credentialStorage
                    )
                } catch (e: RuntimeException) {
                    logger.error("Unexpected exception is thrown", e)
                    Toast.makeText(
                        settingsActivity,
                        "Unexpected error has occurred.",
                        Toast.LENGTH_SHORT
                    ).show()
                    return@OnPreferenceChangeListener false
                }
            }
        findPreference<Preference>(ExperimentalModeConfigProperty.KEY)!!.onPreferenceChangeListener =
            Preference.OnPreferenceChangeListener { _: Preference?, newValue: Any ->
                try {
                    val experimentalMode = newValue as Boolean
                    return@OnPreferenceChangeListener viewModel.setExperimentalMode(
                        experimentalMode
                    )
                } catch (e: RuntimeException) {
                    logger.error("Unexpected exception is thrown", e)
                    Toast.makeText(
                        settingsActivity,
                        "Unexpected error has occurred.",
                        Toast.LENGTH_SHORT
                    ).show()
                    return@OnPreferenceChangeListener false
                }
            }
        findPreference<Preference>(DeveloperModeConfigProperty.KEY)!!.onPreferenceChangeListener =
            Preference.OnPreferenceChangeListener { _: Preference?, newValue: Any ->
                try {
                    val developerMode = newValue as Boolean
                    return@OnPreferenceChangeListener viewModel.setDeveloperMode(
                        developerMode
                    )
                } catch (e: RuntimeException) {
                    logger.error("Unexpected exception is thrown", e)
                    Toast.makeText(
                        settingsActivity,
                        "Unexpected error has occurred.",
                        Toast.LENGTH_SHORT
                    ).show()
                    return@OnPreferenceChangeListener false
                }
            }
        findPreference<Preference>(CONFIG_RESET_KEY)!!.let {
            it.onPreferenceClickListener = Preference.OnPreferenceClickListener {
                ConfigurationsResetConfirmationDialogUtil.confirm(requireContext()){ confirmed ->
                    if(confirmed){
                        configManager.reset()
                    }
                }
                return@OnPreferenceClickListener true
            }
        }
    }

    private fun setupNFCAdapterEnabledListener() {
        nfcService.isNFCAdapterEnabled.observe(this, this::onNFCAdapterEnabledChanged)
        onNFCAdapterEnabledChanged(nfcService.isNFCAdapterEnabled.value!!) // call eventHandler explicitly to reflect current status
    }

    private fun tearDownNFCEnabledListener() {
        nfcService.isNFCAdapterEnabled.removeObserver(this::onNFCAdapterEnabledChanged)
    }

    private fun setupBLEAdapterEnabledListener() {
        bleService.isBLEAdapterEnabled.observe(this, this::onBLEAdapterEnabledChanged)
        onBLEAdapterEnabledChanged(bleService.isBLEAdapterEnabled.value!!) // call eventHandler explicitly to reflect current status
    }

    private fun tearDownBLEAdapterEnabledListener() {
        bleService.isBLEAdapterEnabled.removeObserver(this::onBLEAdapterEnabledChanged)
    }

    private fun onNFCAdapterEnabledChanged(enabled: Boolean) {
        val nfcTransportEnabledPreference =
            findPreference<SwitchPreferenceCompat>(NFCTransportEnabledConfigProperty.KEY)!!
        nfcTransportEnabledPreference.isEnabled = enabled
    }

    private fun onBLEAdapterEnabledChanged(enabled: Boolean) {
        val bleEnabledPreference =
            findPreference<SwitchPreferenceCompat>(BLETransportEnabledConfigProperty.KEY)!!
        val bthidPreference =
            findPreference<SwitchPreferenceCompat>(BTHIDTransportEnabledConfigProperty.KEY)!!
        val bluetoothParingPreference = findPreference<Preference>(BTHID_PAIRING_KEY)!!

        bleEnabledPreference.isEnabled = enabled
        bthidPreference.isEnabled = enabled
        bluetoothParingPreference.isEnabled = enabled
    }

    private fun onBLEStatusChanged(bleStatus: BLEStatus) {
        findPreference<Preference>(BTHID_PAIRING_KEY)!!.isEnabled = bleStatus == BLEStatus.ON
    }

    private fun onDeveloperModeChanged(developerMode: Boolean){
        configManager.developerProperties.map {
            findPreference<Preference>(it.key)!!.isVisible = it.enabled
        }
        findPreference<Preference>(DEVELOPER_OPTIONS_KEY)?.isVisible = developerMode
    }

    private fun onExperimentalModeChanged(experimentalMode: Boolean){
        configManager.experimentalProperties.map {
            findPreference<Preference>(it.key)?.isVisible = it.enabled
        }
        findPreference<Preference>(USER_INTERFACE_KEY)?.isVisible = experimentalMode
        findPreference<Preference>(TRANSPORT_KEY)?.isVisible = experimentalMode
    }

    companion object {
        const val BTHID_PAIRING_KEY = "bthidPairing"
        const val CONFIG_RESET_KEY = "configReset"
        const val TRANSPORT_KEY = "transport"
        const val USER_INTERFACE_KEY = "userInterface"
        const val DEVELOPER_OPTIONS_KEY = "developerOptions"
    }

}