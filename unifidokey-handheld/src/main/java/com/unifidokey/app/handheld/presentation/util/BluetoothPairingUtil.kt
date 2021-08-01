package com.unifidokey.app.handheld.presentation.util

import android.bluetooth.BluetoothAdapter
import android.content.Context
import android.content.Intent

object BluetoothPairingUtil {

    fun startPairing(context: Context){
        val discoveryIntent = Intent(BluetoothAdapter.ACTION_REQUEST_DISCOVERABLE)
        discoveryIntent.putExtra(BluetoothAdapter.EXTRA_DISCOVERABLE_DURATION, 180)
        context.startActivity(discoveryIntent)
    }
}