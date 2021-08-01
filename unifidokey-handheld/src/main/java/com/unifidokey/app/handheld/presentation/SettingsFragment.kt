package com.unifidokey.app.handheld.presentation

import android.content.SharedPreferences
import android.content.SharedPreferences.OnSharedPreferenceChangeListener
import android.os.Bundle
import android.widget.Toast
import androidx.preference.ListPreference
import androidx.preference.Preference
import androidx.preference.PreferenceFragmentCompat
import androidx.preference.SwitchPreferenceCompat
import com.unifidokey.R
import com.unifidokey.app.UnifidoKeyComponent
import com.unifidokey.app.handheld.UnifidoKeyHandHeldApplication
import com.unifidokey.app.handheld.presentation.util.BluetoothPairingUtil
import com.unifidokey.core.config.*
import com.unifidokey.core.config.ConfigManager.Companion.BTHID_PAIRING_PREF_KEY
import com.unifidokey.core.service.BLEService
import com.unifidokey.core.service.BLEStatus
import com.unifidokey.core.service.BTHIDService
import com.unifidokey.core.service.NFCService
import com.unifidokey.core.setting.KeepScreenOnSetting
import com.unifidokey.core.setting.KeyStorageSetting
import com.webauthn4j.ctap.authenticator.settings.*
import com.webauthn4j.ctap.authenticator.settings.ResidentKeySetting.Companion.create
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

    override fun onResume() {
        super.onResume()
        setupNFCAdapterEnabledListener()
        setupBLEAdapterEnabledListener()
        bleService.bleStatus.observe(
            viewLifecycleOwner,
            { bleStatus: BLEStatus -> onBLEStatusChanged(bleStatus) })
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

    override fun onSharedPreferenceChanged(sharedPreferences: SharedPreferences, key: String) {
        // Update the value index of ListPreference to reflect the change to the user interface
        val preference = findPreference<Preference>(key)
        if (preference is ListPreference) {
            val newValue = sharedPreferences.getString(key, null)
            preference.setValueIndex(preference.findIndexOfValue(newValue))
        }
    }

    private fun configurePreferences(rootKey: String?) {
        setPreferencesFromResource(R.xml.root_preferences, rootKey)
        preferenceScreen.sharedPreferences.registerOnSharedPreferenceChangeListener(this)
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
            it.isVisible = configManager.nfcFeatureFlag
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
            it.isVisible = configManager.bleFeatureFlag
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
            it.isVisible = configManager.bthidFeatureFlag
        }
        findPreference<Preference>(BTHID_PAIRING_PREF_KEY)!!.let {
            it.onPreferenceClickListener = Preference.OnPreferenceClickListener {
                BluetoothPairingUtil.startPairing(this.requireContext())
                return@OnPreferenceClickListener true
            }
            it.isVisible = configManager.bthidFeatureFlag
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
                    val platformSetting = PlatformSetting.create((newValue as String?)!!)
                    return@OnPreferenceChangeListener viewModel.setPlatformSetting(platformSetting)
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
        findPreference<Preference>(AttestationStatementFormatConfigProperty.KEY)!!.onPreferenceChangeListener =
            Preference.OnPreferenceChangeListener { _: Preference?, newValue: Any? ->
                try {
                    val identifier = AttestationStatementFormatSetting.create((newValue as String))
                    return@OnPreferenceChangeListener viewModel.setAttestationStatementFormatSetting(
                        identifier
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
        val isActive = nfcTransportEnabledPreference.isEnabled && enabled

        //TODO: make event listener and move to CtapNFCAndroidServiceAdapter
        if (isActive) { //Since BLE adaptor cannot be enabled in background, it is explicitly enabled.
            nfcService.enableNFCTransport()
        } else {
            nfcService.disableNFCTransport()
        }
        nfcTransportEnabledPreference.isEnabled = enabled
    }

    private fun onBLEAdapterEnabledChanged(enabled: Boolean) {
        val bleEnabledPreference =
            findPreference<SwitchPreferenceCompat>(BLETransportEnabledConfigProperty.KEY)!!
        val bthidPreference =
            findPreference<SwitchPreferenceCompat>(BTHIDTransportEnabledConfigProperty.KEY)!!
        val bluetoothParingPreference = findPreference<Preference>(BTHID_PAIRING_PREF_KEY)!!

        bleEnabledPreference.isEnabled = enabled
        bthidPreference.isEnabled = enabled
        bluetoothParingPreference.isEnabled = enabled
    }

    private fun onBLEStatusChanged(bleStatus: BLEStatus) {
        findPreference<Preference>(BTHID_PAIRING_PREF_KEY)!!.isEnabled = bleStatus == BLEStatus.ON
    }

}