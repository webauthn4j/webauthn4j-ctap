package com.unifidokey.driver.notification

import android.app.Notification
import android.content.Context

interface UnifidoKeyNotificationController {

    fun createNotification(context: Context): Notification
}