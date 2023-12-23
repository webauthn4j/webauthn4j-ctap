package com.unifidokey.app.handheld.presentation

import android.app.Application
import android.content.Intent
import android.provider.Settings
import android.view.View
import androidx.annotation.UiThread
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.LiveData
import androidx.lifecycle.map
import androidx.navigation.Navigation
import com.google.android.material.checkbox.MaterialCheckBox
import com.unifidokey.R
import com.unifidokey.app.UnifidoKeyComponent
import com.unifidokey.app.handheld.UnifidoKeyHandHeldApplication
import com.unifidokey.core.adapter.BluetoothDeviceHandle
import com.unifidokey.core.config.ConfigManager
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

    val nfcFeatureFlag: Boolean
        get() = configManager.nfcFeatureFlag

    val bleFeatureFlag: Boolean
        get() = configManager.bleFeatureFlag

    val bthidFeatureFlag: Boolean
        get() = configManager.bthidFeatureFlag

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
    fun onNFCToggleButtonClick(view: View) {
        if (!nfcService.isNFCAdapterEnabled.value!!) {
            enableNFCAdapter(view.context as AppCompatActivity)
        }
        if (nfcService.isNFCTransportEnabled.value!!) {
            nfcService.disableNFCTransport()
        } else {
            nfcService.enableNFCTransport()
        }
    }

    @UiThread
    fun onBTHIDToggleButtonClick(view: View) {
        if (!bthidService.isBTHIDAdapterEnabled.value!!) {
            enableBTHIDAdapter(view.context as AppCompatActivity)
        }
        if (bthidService.isBTHIDTransportEnabled.value!!) {
            bthidService.disableBTHIDTransport()
        } else {
            bthidService.enableBTHIDTransport()
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

    @UiThread
    private fun enableNFCAdapter(activity: AppCompatActivity) {
        AlertDialog.Builder(activity)
            .setTitle("UnifidoKey")
            .setMessage("NFC adapter is not enabled. Please enable it from configuration.")
            .setPositiveButton("OK") { _, _ ->
                val intent = Intent(Settings.ACTION_NFC_SETTINGS)
                activity.startActivity(intent)
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    @UiThread
    private fun enableBTHIDAdapter(activity: AppCompatActivity) {
        AlertDialog.Builder(activity)
            .setTitle("UnifidoKey")
            .setMessage("Bluetooth adapter is not enabled. Please enable it from configuration.")
            .setPositiveButton("OK") { _, _ ->
                val intent = Intent(Settings.ACTION_BLUETOOTH_SETTINGS)
                activity.startActivity(intent)
            }
            .setNegativeButton("Cancel", null)
            .show()
    }


}