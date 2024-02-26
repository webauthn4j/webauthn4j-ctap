package com.unifidokey.app.handheld.presentation

import android.app.Application
import android.content.Context
import android.content.Intent
import android.provider.Settings
import android.view.View
import androidx.annotation.UiThread
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.credentials.CredentialManager
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.LiveData
import androidx.lifecycle.MediatorLiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.map
import androidx.navigation.Navigation
import com.google.android.material.checkbox.MaterialCheckBox
import com.unifidokey.R
import com.unifidokey.app.UnifidoKeyComponent
import com.unifidokey.app.handheld.UnifidoKeyHandHeldApplication
import com.unifidokey.core.adapter.BluetoothDeviceHandle
import com.unifidokey.core.config.ConfigManager
import com.unifidokey.core.config.ReleaseLevel
import com.unifidokey.core.service.AuthenticatorService
import com.unifidokey.core.service.BTHIDService
import com.unifidokey.core.service.BTHIDStatus
import com.unifidokey.core.service.NFCService
import com.unifidokey.core.service.NFCStatus
import com.webauthn4j.ctap.authenticator.data.event.Event
import com.webauthn4j.data.attestation.statement.AndroidSafetyNetAttestationStatement
import com.webauthn4j.data.attestation.statement.NoneAttestationStatement
import org.slf4j.LoggerFactory


class HomeViewModel(application: Application) : AndroidViewModel(application) {

    private val logger = LoggerFactory.getLogger(HomeViewModel::class.java)
    private val unifidoKeyComponent: UnifidoKeyComponent =
        (application as UnifidoKeyHandHeldApplication).unifidoKeyComponent
    private val authenticatorService: AuthenticatorService =
        unifidoKeyComponent.authenticatorService
    private val configManager: ConfigManager = unifidoKeyComponent.configManager
    private val nfcService: NFCService = unifidoKeyComponent.nfcService
    private val bthidService: BTHIDService = unifidoKeyComponent.bthidService

    val isNoneAttestation = configManager.attestationStatementFormat.liveData.map {
        it.value == NoneAttestationStatement.FORMAT
    }

    val isAndroidSafetyNetAttestation = configManager.attestationStatementFormat.liveData.map {
        it.value == AndroidSafetyNetAttestationStatement.FORMAT
    }

    val nfcCardVisibility : LiveData<Boolean> = configManager.experimentalMode.liveData.map {
        if(configManager.isNFCTransportEnabled.releaseLevel == ReleaseLevel.PRIVATE){
           return@map false
        }
        return@map it
    }

    val bthidCardVisibility : LiveData<Boolean> = configManager.experimentalMode.liveData.map {
        if(configManager.isBTHIDTransportEnabled.releaseLevel == ReleaseLevel.PRIVATE){
            return@map false
        }
        return@map it
    }

    val bthidDevices: LiveData<List<BluetoothDeviceHandle>>
        get() = bthidService.bluetoothDevices

    val recentEvents: LiveData<List<Event>> =
        authenticatorService.events.map { events -> events.take(3) }

    val isBTHIDBackgroundServiceModeEnabled: LiveData<Boolean>
        get() = bthidService.isBTHIDBackgroundServiceModeEnabled

    val hybridInternalStatusMessage = "Hybrid/Internal transport is Supported" //TODO: check OS version

    val nfcStatusMessage = nfcService.nfcStatus.map {
        when (it) {
            NFCStatus.ON -> "NFC transport is ON"
            NFCStatus.OFF -> "NFC transport is OFF"
            NFCStatus.NOT_AVAILABLE -> "NFC transport is not available"
            else -> throw IllegalStateException("Unexpected NFCStatus")
        }
    }
    val nfcButtonText = nfcService.nfcStatus.map {
        when (it) {
            NFCStatus.ON -> "Disable"
            NFCStatus.OFF -> "Enable"
            NFCStatus.NOT_AVAILABLE -> "Enable"
            else -> throw IllegalStateException("Unexpected NFCStatus")
        }
    }
    val isNFCAdapterAvailable: Boolean
        get() = nfcService.isNFCAdapterAvailable

    val bthidStatusMessage = bthidService.bthidStatus.map {
        when (it) {
            BTHIDStatus.ON -> "Bluetooth HID transport is ON"
            BTHIDStatus.OFF -> "Bluetooth HID transport is OFF"
            BTHIDStatus.NOT_AVAILABLE -> "Bluetooth HID transport is not available"
            else -> throw IllegalStateException("Unexpected BTHIDStatus")
        }
    }
    val bthidButtonText = bthidService.bthidStatus.map {
        when (it) {
            BTHIDStatus.ON -> "Disable"
            BTHIDStatus.OFF -> "Enable"
            BTHIDStatus.NOT_AVAILABLE -> "Enable"
            else -> throw IllegalStateException("Unexpected BTHIDStatus")
        }
    }
    val isBTHIDAdapterAvailable: Boolean
        get() = bthidService.isBTHIDAdapterAvailable

    @UiThread
    fun onHybridInternalButtonClick(view: View) {
        showPasskeyProviderSetting(view.context)
    }

    @UiThread
    fun onNFCToggleButtonClick(view: View) {
        if (nfcService.isNFCAdapterEnabled.value != true) {
            showNFCAdapterActivationGuideDialog(view.context)
        }
        if (nfcService.isNFCAdapterEnabled.value == true) {
            configManager.isNFCTransportEnabled.value = !configManager.isNFCTransportEnabled.value
        }
    }

    @UiThread
    fun onBTHIDToggleButtonClick(view: View) {
        if (bthidService.isBTHIDAdapterEnabled.value != true) {
            showBTHIDAdapterActivationGuideDialog(view.context)
        }
        if (bthidService.isBTHIDAdapterEnabled.value == true) {
            configManager.isBTHIDTransportEnabled.value = !configManager.isBTHIDTransportEnabled.value
        }
    }

    @UiThread
    fun onBTHIDStayBackgroundButtonClick(view: View) {
        val checkbox = view as MaterialCheckBox
        configManager.isBTHIDBackgroundServiceModeEnabled.value = checkbox.isChecked
    }

    @UiThread
    fun onHistoryMoreButtonClick(view: View) {
        Navigation.findNavController(view).navigate(R.id.historyFragment)
    }

    private fun showPasskeyProviderSetting(context: Context) {
        val intent = CredentialManager.create(context).createSettingsPendingIntent()
        intent.send()
    }

    @UiThread
    private fun showNFCAdapterActivationGuideDialog(context: Context) {
        AlertDialog.Builder(context)
            .setTitle("UnifidoKey")
            .setMessage("NFC adapter is not enabled. Please enable it from configuration.")
            .setPositiveButton("OK") { _, _ ->
                val intent = Intent(Settings.ACTION_NFC_SETTINGS)
                context.startActivity(intent)
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    @UiThread
    private fun showBTHIDAdapterActivationGuideDialog(context: Context) {
        AlertDialog.Builder(context)
            .setTitle("UnifidoKey")
            .setMessage("Bluetooth adapter is not enabled. Please enable it from configuration.")
            .setPositiveButton("OK") { _, _ ->
                val intent = Intent(Settings.ACTION_BLUETOOTH_SETTINGS)
                context.startActivity(intent)
            }
            .setNegativeButton("Cancel", null)
            .show()
    }


}