package com.unifidokey.core.adapter

import androidx.lifecycle.LiveData

interface CtapBTHIDAdapter {

    fun connect(deviceHandle: BluetoothDeviceHandle)
    fun disconnect(deviceHandle: BluetoothDeviceHandle)

    val isBTHIDAdapterAvailable: Boolean
    val isBTHIDAdapterEnabled: LiveData<Boolean>
    val bluetoothDevices: LiveData<List<BluetoothDeviceHandle>>
}