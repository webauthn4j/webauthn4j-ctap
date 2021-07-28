package com.unifidokey.app.handheld.presentation

import android.content.Context
import android.view.View
import android.widget.Toast
import androidx.lifecycle.LiveData
import androidx.lifecycle.ViewModel
import com.unifidokey.core.adapter.BluetoothDeviceHandle
import com.unifidokey.core.service.BTHIDService
import com.unifidokey.core.service.BTHIDStatus

class BTHIDDeviceViewModel(
    private val context: Context,
    private val bthidService: BTHIDService,
    private val deviceHandle: BluetoothDeviceHandle
) : ViewModel() {

    val name: String
        get() = deviceHandle.name

    val connectionState: LiveData<String> = deviceHandle.connectionState

    @Suppress("UNUSED_PARAMETER")
    fun onClick(view: View) {
        if (bthidService.bthidStatus.value != BTHIDStatus.ON) {
            Toast.makeText(context, "Bluetooth HID is not enabled.", Toast.LENGTH_SHORT).show()
        }
        bthidService.toggleConnection(deviceHandle)
    }
}