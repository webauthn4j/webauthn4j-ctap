package com.unifidokey.driver.device

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import com.unifidokey.app.UnifidoKeyApplicationBase
import com.unifidokey.driver.transport.CtapBTHIDAndroidServiceContextualAdapter

class DeviceBootBroadcastReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent?) {
        val unifidoKeyApplication = context.applicationContext as UnifidoKeyApplicationBase<*>
        val bthidServiceContextualAdapter = unifidoKeyApplication.unifidoKeyComponent.bthidServiceContextualAdapter
        bthidServiceContextualAdapter.startService()
    }

}