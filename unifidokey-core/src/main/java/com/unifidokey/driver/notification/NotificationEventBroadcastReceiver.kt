package com.unifidokey.driver.notification

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import com.unifidokey.app.UnifidoKeyApplicationBase

class NotificationEventBroadcastReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent?) {
        val unifidoKeyApplication = context.applicationContext as UnifidoKeyApplicationBase<*>
        val configManager = unifidoKeyApplication.unifidoKeyComponent.configManager
        configManager.isBTHIDBackgroundServiceModeEnabled.value = false
    }
}