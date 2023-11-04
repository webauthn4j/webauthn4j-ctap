package com.unifidokey.app.handheld.presentation

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Context.NOTIFICATION_SERVICE
import android.content.Intent
import androidx.core.app.NotificationCompat
import com.unifidokey.core.R
import com.unifidokey.driver.notification.NotificationEventBroadcastReceiver
import com.unifidokey.driver.notification.UnifidoKeyNotificationController
import com.unifidokey.driver.transport.CtapBTHIDAndroidService

class UnifidoKeyHandHeldNotificationController : UnifidoKeyNotificationController {

    override fun createNotification(context: Context): Notification {
        val notificationChannel = createOrGetNotificationChannel(context)
        val contentIntent = Intent(context, MainActivity::class.java)
        val pendingContentIntent: PendingIntent =
            PendingIntent.getActivity(context, 0, contentIntent, PendingIntent.FLAG_IMMUTABLE)
        val turnoffActionIntent =
            Intent(context, NotificationEventBroadcastReceiver::class.java).apply {
                action =
                    "com.unifidokey.driver.notification.UnifidoKeyHandHeldNotificationController.action.TURN_OFF"
            }
        val pendingTurnoffActionIntent: PendingIntent =
            PendingIntent.getBroadcast(context, 0, turnoffActionIntent, 0)
        val turnoffAction = NotificationCompat.Action.Builder(
            R.drawable.ic_notification,
            "Turn off",
            pendingTurnoffActionIntent
        ).build()
        return NotificationCompat.Builder(context, notificationChannel.id)
            .setContentTitle("UnifidoKey Bluetooth HID service")
            .setContentText("Ready for background Bluetooth connection")
            .setSmallIcon(R.drawable.ic_notification)
            .setChannelId(notificationChannel.id)
            .setShowWhen(false)
            .setContentIntent(pendingContentIntent)
            .addAction(turnoffAction)
            .build()
    }

    private fun createOrGetNotificationChannel(context: Context): NotificationChannel {
        val notificationManager =
            context.getSystemService(NOTIFICATION_SERVICE) as NotificationManager
        if (notificationManager.getNotificationChannel(CtapBTHIDAndroidService.UNIFIDOKEY_NOTIFICATION_CHANNEL_ID) == null) {
            val name = "UnifidoKey"
            val notificationChannel = NotificationChannel(
                CtapBTHIDAndroidService.UNIFIDOKEY_NOTIFICATION_CHANNEL_ID,
                name,
                NotificationManager.IMPORTANCE_LOW
            )
            notificationChannel.description = "UnifidoKey Notifications"
            notificationChannel.setShowBadge(false)
            notificationManager.createNotificationChannel(notificationChannel)
        }
        return notificationManager.getNotificationChannel(CtapBTHIDAndroidService.UNIFIDOKEY_NOTIFICATION_CHANNEL_ID)
    }
}