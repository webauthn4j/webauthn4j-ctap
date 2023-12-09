package com.unifidokey.driver.transport

import android.Manifest
import android.bluetooth.BluetoothManager
import android.bluetooth.le.AdvertiseCallback
import android.bluetooth.le.AdvertiseData
import android.bluetooth.le.AdvertiseSettings
import android.bluetooth.le.BluetoothLeAdvertiser
import android.os.ParcelUuid
import androidx.annotation.RequiresPermission

class Fido2Advertiser(bluetoothManager: BluetoothManager) {

    private val bleAdvertiser: BluetoothLeAdvertiser
    private val fido2AdvertiseCallback = Fido2AdvertiseCallback()

    @RequiresPermission(Manifest.permission.BLUETOOTH_ADVERTISE)
    fun startBLEAdvertise() {
        val settingBuilder = AdvertiseSettings.Builder()
        settingBuilder.setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_POWER)
        settingBuilder.setConnectable(true)
        settingBuilder.setTimeout(0)
        settingBuilder.setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_LOW)
        val settings = settingBuilder.build()
        val advertiseDataBuilder = AdvertiseData.Builder()
        advertiseDataBuilder.setIncludeDeviceName(true)
        advertiseDataBuilder.setIncludeTxPowerLevel(true)
        advertiseDataBuilder.addServiceUuid(ParcelUuid(Fido2BLEGATTServer.FIDO2_GATT_SERVICE_UUID))
        advertiseDataBuilder.addServiceUuid(ParcelUuid(Fido2BLEGATTServer.DEVICE_INFORMATION_SERVICE_UUID))
        val advertiseData = advertiseDataBuilder.build()
        bleAdvertiser.startAdvertising(settings, advertiseData, fido2AdvertiseCallback)
    }

    @RequiresPermission(Manifest.permission.BLUETOOTH_ADVERTISE)
    fun stopBLEAdvertise() {
        bleAdvertiser.stopAdvertising(fido2AdvertiseCallback)
    }

    private class Fido2AdvertiseCallback : AdvertiseCallback() {
        override fun onStartSuccess(settingsInEffect: AdvertiseSettings) {
            super.onStartSuccess(settingsInEffect)
        }

    }

    init {
        val bleAdapter = bluetoothManager.adapter
        bleAdvertiser = bleAdapter.bluetoothLeAdvertiser
    }
}