package com.unifidokey.driver.device

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import com.unifidokey.app.UnifidoKeyApplicationBase
import org.slf4j.LoggerFactory

class DeviceBootBroadcastReceiver : BroadcastReceiver() {

    private val logger =
        LoggerFactory.getLogger(DeviceBootBroadcastReceiver::class.java)

    override fun onReceive(context: Context, intent: Intent) {
        logger.debug("onReceive")
        when (intent.action) {
            Intent.ACTION_BOOT_COMPLETED -> {
                val unifidoKeyApplication = context.applicationContext as UnifidoKeyApplicationBase<*>
                val bthidServiceContextualAdapter = unifidoKeyApplication.unifidoKeyComponent.bthidServiceContextualAdapter
                if(unifidoKeyApplication.unifidoKeyComponent.bthidService.isBTHIDBackgroundServiceModeEnabled.value == true){
                    bthidServiceContextualAdapter.startForegroundService()
                }
            }
        }
    }

}