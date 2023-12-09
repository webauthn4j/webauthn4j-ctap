package com.unifidokey.driver.transport

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.bluetooth.BluetoothManager
import android.content.Context
import android.content.Intent
import android.os.Binder
import android.os.IBinder
import androidx.annotation.RequiresPermission
import androidx.core.app.NotificationCompat
import com.unifidokey.app.UnifidoKeyApplicationBase
import com.unifidokey.core.service.AuthenticatorService
import org.slf4j.LoggerFactory

/**
 * Android service for managing CTAP over BLE. It retrieves [AuthenticatorService] instance
 * from Dagger2 container and initialize [Fido2BLEGATTServer] with it.
 *
</T> */
class CtapBLEAndroidService : Service() {

    companion object {
        private const val ACTION_START_ADVERTISE = "ACTION_START_ADVERTISE"
        const val NOTIFICATION_ID = 1
        const val UNIFIDOKEY_NOTIFICATION_CHANNEL_ID = "UnifidoKeyNotificationChannel"
    }

    private val logger = LoggerFactory.getLogger(CtapBLEAndroidService::class.java)
    private lateinit var fido2BLEGATTServer: Fido2BLEGATTServer
    private lateinit var fido2Advertiser: Fido2Advertiser
    private val ctapBLEDroidServiceBinder = CtapBLEDroidServiceBinder()

    override fun onCreate() {
        super.onCreate()
        initialize()
    }

    override fun onStartCommand(intent: Intent, flags: Int, startId: Int): Int {
        return START_STICKY
    }

    override fun onBind(intent: Intent): IBinder {
        return ctapBLEDroidServiceBinder
    }

    private fun initialize() {
        val unifidoKeyApplication = application as UnifidoKeyApplicationBase<*>
        val ctapAuthenticator = unifidoKeyApplication.unifidoKeyComponent.authenticatorService.ctapAuthenticator
        val context = applicationContext
        val bluetoothManager = getSystemService(BLUETOOTH_SERVICE) as BluetoothManager
        fido2BLEGATTServer = Fido2BLEGATTServer(context, bluetoothManager, ctapAuthenticator)
        fido2Advertiser = Fido2Advertiser(bluetoothManager)
        logger.debug("CtapBLEAndroidService is initialized")
    }

    private fun startNotification(context: Context) {
        val notificationManager = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
        if (notificationManager.getNotificationChannel(UNIFIDOKEY_NOTIFICATION_CHANNEL_ID) == null) {
            val name = "UnifidoKey"
            val notificationChannel = NotificationChannel(
                UNIFIDOKEY_NOTIFICATION_CHANNEL_ID,
                name,
                NotificationManager.IMPORTANCE_HIGH
            )
            notificationChannel.description = "UnifidoKey Notifications"
            notificationManager.createNotificationChannel(notificationChannel)
        }
        val notification = NotificationCompat.Builder(context, UNIFIDOKEY_NOTIFICATION_CHANNEL_ID)
            .setContentTitle("UnifidoKey BLE Service")
            .setContentText("UnifidoKey BLE Service is running")
            .setShowWhen(false)
            .build()
        startForeground(NOTIFICATION_ID, notification)
    }

    @RequiresPermission(Manifest.permission.BLUETOOTH_ADVERTISE)
    fun startAdvertise() {
        fido2Advertiser.startBLEAdvertise()
    }

    @RequiresPermission(Manifest.permission.BLUETOOTH_ADVERTISE)
    fun stopAdvertise() {
        fido2Advertiser.stopBLEAdvertise()
    }

    internal inner class CtapBLEDroidServiceBinder : Binder() {
        val service: CtapBLEAndroidService
            get() = this@CtapBLEAndroidService
    }

}