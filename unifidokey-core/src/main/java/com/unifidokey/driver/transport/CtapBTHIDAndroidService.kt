package com.unifidokey.driver.transport

import android.app.*
import android.bluetooth.*
import android.bluetooth.BluetoothProfile.*
import android.content.Intent
import android.os.Binder
import android.os.IBinder
import androidx.annotation.MainThread
import androidx.annotation.WorkerThread
import androidx.lifecycle.*
import com.unifidokey.app.UnifidoKeyApplicationBase
import com.unifidokey.core.adapter.BluetoothDeviceHandle
import com.unifidokey.core.config.BTHIDDeviceHistoryConfigProperty
import com.unifidokey.core.config.BTHIDDeviceHistoryEntry
import com.unifidokey.core.service.BTHIDService
import com.unifidokey.core.service.BTHIDStatus
import com.unifidokey.driver.notification.UnifidoKeyNotificationController
import com.webauthn4j.converter.util.ObjectConverter
import com.webauthn4j.ctap.authenticator.Connection
import com.webauthn4j.ctap.authenticator.CtapAuthenticator
import com.webauthn4j.ctap.core.data.hid.HIDMessage.Companion.MAX_PACKET_SIZE
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import org.slf4j.LoggerFactory
import java.time.Instant

class CtapBTHIDAndroidService : Service(), Observer<BTHIDStatus>, LifecycleObserver {

    companion object {
        private const val ACTION_START_ADVERTISE = "ACTION_START_ADVERTISE"
        const val NOTIFICATION_ID = 1
        const val UNIFIDOKEY_NOTIFICATION_CHANNEL_ID = "UnifidoKeyNotificationChannel"

        private val HID_REPORT_DESC = byteArrayOf(
            0x06.toByte(), 0xD0.toByte(), 0xF1.toByte(), // Usage Page (FIDO_USAGE_PAGE, 2 bytes)
            0x09.toByte(), 0x01.toByte(),                // Usage (FIDO_USAGE_U2FHID)
            0xA1.toByte(), 0x01.toByte(),                // Collection (Application)

            0x09.toByte(), 0x20.toByte(),                // Usage (FIDO_USAGE_DATA_IN)
            0x15.toByte(), 0x00.toByte(),                // Logical Minimum (0)
            0x26.toByte(), 0xFF.toByte(), 0x00.toByte(), // Logical Maximum (255, 2 bytes)
            0x75.toByte(), 0x08.toByte(),                // Report Size (8)
            0x95.toByte(), MAX_PACKET_SIZE.toByte(),     // Report Count (variable)
            0x81.toByte(), 0x02.toByte(),                // Input (Data, Absolute, Variable)

            0x09.toByte(), 0x21.toByte(),                // Usage (FIDO_USAGE_DATA_OUT)
            0x15.toByte(), 0x00.toByte(),                // Logical Minimum (0)
            0x26.toByte(), 0xFF.toByte(), 0x00.toByte(), // Logical Maximum (255, 2 bytes)
            0x75.toByte(), 0x08.toByte(),                // Report Size (8)
            0x95.toByte(), MAX_PACKET_SIZE.toByte(),     // Report Count (variable)
            0x91.toByte(), 0x02.toByte(),                // Output (Data, Absolute, Variable)

            0xC0.toByte()                                // End Collection
        )
    }

    private val logger = LoggerFactory.getLogger(CtapBTHIDAndroidService::class.java)
    private lateinit var ctapAuthenticator: CtapAuthenticator
    private lateinit var bthidService: BTHIDService
    private lateinit var objectConverter: ObjectConverter
    private lateinit var unifidoKeyNotificationController: UnifidoKeyNotificationController
    private lateinit var bthidDeviceHistory: BTHIDDeviceHistoryConfigProperty

    private var connection: Connection? = null

    private var bluetoothAdapter: BluetoothAdapter = BluetoothAdapter.getDefaultAdapter()
    private var bluetoothHidDevice: BluetoothHidDevice? = null
    private val ctapBLEDroidServiceBinder = CtapBTHIDAndroidServiceBinder()
    private val hidProfileServiceListener = HIDProfileServiceListener()

    @MainThread
    override fun onCreate() {
        logger.debug("onCreate")
        super.onCreate()
        registerServiceListener()
        initialize()
        bthidService.bthidStatus.observeForever(this)
        ProcessLifecycleOwner.get().lifecycle.addObserver(this)
    }

    @MainThread
    override fun onDestroy() {
        logger.debug("onDestroy")
        super.onDestroy()
        unregisterServiceListener()
        bthidService.bthidStatus.removeObserver(this)
        ProcessLifecycleOwner.get().lifecycle.removeObserver(this)
    }

    @OnLifecycleEvent(Lifecycle.Event.ON_RESUME)
    fun onResume() {
        logger.debug("onResume")
        hidProfileServiceListener.configureApp() // As the App is unregistered on pause, re-register on resume.
    }

    @OnLifecycleEvent(Lifecycle.Event.ON_PAUSE)
    fun onPause() {
        logger.debug("onPause")

    }

    @MainThread
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        logger.debug("onStartCommand")
        startForegroundIfNecessary()
        return super.onStartCommand(intent, flags, startId)
    }

    @WorkerThread
    override fun onBind(intent: Intent?): IBinder {
        logger.debug("onBind")
        return ctapBLEDroidServiceBinder
    }

    override fun onRebind(intent: Intent?) {
        logger.debug("onRebind")
    }

    @WorkerThread
    override fun onUnbind(intent: Intent?): Boolean {
        logger.debug("onUnbind")
        return true
    }

    override fun onChanged(bthidStatus: BTHIDStatus) {
        hidProfileServiceListener.isAppEnabled = bthidStatus == BTHIDStatus.ON
    }

    fun connect(deviceHandle: BluetoothDeviceHandle) {
        connection = ctapAuthenticator.connect()
        val remoteDevice = bluetoothAdapter.getRemoteDevice(deviceHandle.address)
        val result = bluetoothHidDevice?.connect(remoteDevice)!!
        if (result) {
            val history: List<BTHIDDeviceHistoryEntry>? = bthidDeviceHistory.value
            history?.firstOrNull { it.address == deviceHandle.address }?.lastConnectedAt =
                Instant.now()
            bthidDeviceHistory.value = history
        }
    }

    fun disconnect(deviceHandle: BluetoothDeviceHandle) {
        val remoteDevice = bluetoothAdapter.getRemoteDevice(deviceHandle.address)
        bluetoothHidDevice?.disconnect(remoteDevice)
        connection = null
    }

    @MainThread
    private fun initialize() {
        val unifidoKeyApplication = application as UnifidoKeyApplicationBase<*>
        ctapAuthenticator = unifidoKeyApplication.unifidoKeyComponent.authenticatorService.ctapAuthenticator
        bthidService = unifidoKeyApplication.unifidoKeyComponent.bthidService
        objectConverter = unifidoKeyApplication.unifidoKeyComponent.objectConverter
        unifidoKeyNotificationController =
            unifidoKeyApplication.unifidoKeyComponent.unifidoKeyNotificationController
        bthidDeviceHistory =
            unifidoKeyApplication.unifidoKeyComponent.configManager.bthidDeviceHistory
        bthidService.isBTHIDBackgroundServiceModeEnabled.observeForever {
            when {
                it -> startForeground()
                else -> stopForeground(true)
            }
        }
        logger.debug("CtapBTHIDAndroidService is initialized")
    }

    @MainThread
    fun registerServiceListener() {
        bluetoothAdapter.getProfileProxy(this, hidProfileServiceListener, HID_DEVICE)
    }

    @MainThread
    fun unregisterServiceListener() {
        if (bluetoothHidDevice != null) {
            bluetoothAdapter.closeProfileProxy(HID_DEVICE, bluetoothHidDevice)
        }
    }

    private fun startForegroundIfNecessary() {
        if (bthidService.isBTHIDBackgroundServiceModeEnabled.value == true) {
            startForeground()
        }
    }

    fun startForeground() {
        val notification = unifidoKeyNotificationController.createNotification(this)
        startForeground(NOTIFICATION_ID, notification)
    }

    private inner class HIDProfileServiceListener : ServiceListener {

        private val bluetoothHidDeviceAppSdpSettings = BluetoothHidDeviceAppSdpSettings(
            "UnifidoKey",
            "FIDO2 Security Key",
            "WebAuthn4J",
            BluetoothHidDevice.SUBCLASS1_COMBO,
            HID_REPORT_DESC
        )
        private val outQosSettings = BluetoothHidDeviceAppQosSettings(
            BluetoothHidDeviceAppQosSettings.SERVICE_BEST_EFFORT,
            1000,
            MAX_PACKET_SIZE + 1, //元々は MAX_PACKET_SIZE + 1, //TODO： +1って何？
            2000,
            5000,
            BluetoothHidDeviceAppQosSettings.MAX
        )

        var isAppEnabled = false
            set(value) {
                field = value
                configureApp()
            }

        override fun onServiceConnected(profile: Int, proxy: BluetoothProfile?) {
            CoroutineScope(Dispatchers.IO).launch {
                bluetoothHidDevice = proxy as BluetoothHidDevice
                if (isAppEnabled) {
                    registerApp()
                }
//                setupBluetoothDeviceConnection()
            }
        }

        override fun onServiceDisconnected(profile: Int) {
            CoroutineScope(Dispatchers.IO).launch {
                logger.debug("onServiceDisconnected")
                unregisterApp()
            }
        }

        fun configureApp() {
            if (bluetoothHidDevice != null) {
                if (isAppEnabled) {
                    registerApp()
                } else {
                    unregisterApp()
                }
            }
        }

        private fun registerApp() {
            bluetoothHidDevice.let { bluetoothHidDevice ->
                requireNotNull(bluetoothHidDevice) { "bluetoothHidDevice must not be null" }
                connection.let {
                    requireNotNull(it) { "connection must not be null" }
                    bluetoothHidDevice.registerApp(
                        bluetoothHidDeviceAppSdpSettings,
                        null,
                        outQosSettings,
                        Runnable::run,
                        Fido2BTHIDApplication(it, bluetoothHidDevice, objectConverter)
                    )
                }
            }
        }

        private fun unregisterApp() {
            bluetoothHidDevice.let { bluetoothHidDevice ->
                requireNotNull(bluetoothHidDevice) { "bluetoothHidDevice must not be null" }
                bluetoothHidDevice.unregisterApp()
            }
        }

//        /**
//         * If the configured bluetooth device is not connected,
//         * connect to the bluetooth device
//         */
//        private fun setupBluetoothDeviceConnection(){
//            //TODO: 接続されているかチェックし、接続されていない場合のみ、接続するように修正
//            connectedDevice?.let {
//                val device = bluetoothAdapter.getRemoteDevice(connectedDevice)
//                bluetoothHidDevice?.let {
//                    val connectionState = it.getConnectionState(device)
//                    when(connectionState){
//                        STATE_DISCONNECTED -> logger.debug("state disconnected")
//                        STATE_CONNECTING -> logger.debug("state connecting")
//                        STATE_CONNECTED -> logger.debug("state connected")
//                        STATE_DISCONNECTING -> logger.debug("state disconnecting")
//                    }
//                    logger.debug("connect to {}", connectedDevice)
//                    it.connect(device)
//                }
//            }
//        }

    }

    internal inner class CtapBTHIDAndroidServiceBinder : Binder() {

        val service: CtapBTHIDAndroidService
            get() = this@CtapBTHIDAndroidService
    }


}