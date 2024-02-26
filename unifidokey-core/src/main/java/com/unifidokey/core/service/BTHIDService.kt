package com.unifidokey.core.service

import androidx.annotation.UiThread
import androidx.lifecycle.LiveData
import androidx.lifecycle.MediatorLiveData
import com.unifidokey.core.adapter.BluetoothDeviceHandle
import com.unifidokey.core.adapter.CtapBTHIDAdapter
import com.unifidokey.core.config.ConfigManager
import com.webauthn4j.ctap.core.util.internal.BooleanUtil

class BTHIDService constructor(
    private val configManager: ConfigManager,
    private val ctapBTHIDAdapter: CtapBTHIDAdapter
) {

    private val _bthidStatus = MediatorLiveData<BTHIDStatus>()

    val bthidStatus: LiveData<BTHIDStatus>
        get() = _bthidStatus

    val isBTHIDAdapterAvailable: Boolean
        get() = ctapBTHIDAdapter.isBTHIDAdapterAvailable
    val isBTHIDAdapterEnabled: LiveData<Boolean>
        get() = ctapBTHIDAdapter.isBTHIDAdapterEnabled
    val isBTHIDTransportEnabled: LiveData<Boolean>
        get() = configManager.isBTHIDTransportEnabled.liveData
    val bluetoothDevices: LiveData<List<BluetoothDeviceHandle>>
        get() = ctapBTHIDAdapter.bluetoothDevices
    val isBTHIDBackgroundServiceModeEnabled: LiveData<Boolean>
        get() = configManager.isBTHIDBackgroundServiceModeEnabled.liveData

    private val currentStatus: BTHIDStatus
        get() = when {
            !configManager.bthidFeatureFlag -> BTHIDStatus.NOT_AVAILABLE
            !isBTHIDAdapterAvailable -> BTHIDStatus.NOT_AVAILABLE
            BooleanUtil.isTrue(isBTHIDTransportEnabled.value) && BooleanUtil.isTrue(
                isBTHIDAdapterEnabled.value
            ) -> BTHIDStatus.ON
            else -> BTHIDStatus.OFF
        }

    init {
        _bthidStatus.value = currentStatus
        _bthidStatus.addSource(isBTHIDTransportEnabled) {
            _bthidStatus.value = currentStatus
        }
        _bthidStatus.addSource(isBTHIDAdapterEnabled) {
            _bthidStatus.value = currentStatus
        }
        _bthidStatus.observeForever{
            when(it){
                BTHIDStatus.ON -> {
                    enableBTHIDTransport()
                }
                else -> {
                    disableBTHIDTransport()
                }
            }
        }
    }

    @UiThread
    fun enableBTHIDTransport() {
        configManager.isBTHIDTransportEnabled.value = true
    }

    @UiThread
    fun disableBTHIDTransport() {
        configManager.isBTHIDTransportEnabled.value = false
    }


    @UiThread
    fun toggleConnection(deviceHandle: BluetoothDeviceHandle) {
        // disconnect all devices
        bluetoothDevices.value?.forEach {
            ctapBTHIDAdapter.disconnect(it)
        }
        if (deviceHandle.connectionState.value == "connected") {
            ctapBTHIDAdapter.disconnect(deviceHandle)
        } else {
            ctapBTHIDAdapter.connect(deviceHandle)
        }
    }
}