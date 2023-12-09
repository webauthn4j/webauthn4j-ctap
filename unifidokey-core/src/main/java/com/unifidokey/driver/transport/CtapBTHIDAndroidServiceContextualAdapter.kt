package com.unifidokey.driver.transport

import android.Manifest
import android.app.Service
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothClass.Device
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothDevice.DEVICE_TYPE_LE
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothProfile
import android.content.*
import android.content.pm.PackageManager
import android.os.IBinder
import androidx.annotation.RequiresPermission
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.core.content.ContextCompat.getSystemService
import androidx.lifecycle.LiveData
import androidx.lifecycle.MediatorLiveData
import androidx.lifecycle.MutableLiveData
import com.unifidokey.app.UnifidoKeyApplicationBase
import com.unifidokey.core.adapter.BluetoothDeviceHandle
import com.unifidokey.core.adapter.CtapBTHIDAdapter
import com.unifidokey.core.config.BTHIDDeviceHistoryEntry
import org.slf4j.LoggerFactory
import java.time.Instant


class CtapBTHIDAndroidServiceContextualAdapter(private val applicationContext: Context) :
    CtapBTHIDAdapter, AutoCloseable {

    private val logger =
        LoggerFactory.getLogger(CtapBTHIDAndroidServiceContextualAdapter::class.java)

    private val packageManager: PackageManager = applicationContext.packageManager
    private val bluetoothManager = getSystemService(applicationContext, BluetoothManager::class.java)!!
    private val bluetoothAdapter: BluetoothAdapter? by lazy {
        bluetoothManager.adapter
    }
    private var ctapBTHIDAndroidService: CtapBTHIDAndroidService? = null
    private var ctapBTHIDDroidServiceConnection: CtapBTHIDAndroidServiceContextualAdapter.CtapBTHIDDroidServiceConnection? =
        null

    private val bthidBroadcastReceiver = BTHIDBroadcastReceiver()

    override val bluetoothDevices: LiveData<List<BluetoothDeviceHandle>> by lazy {
        MediatorLiveData<List<BluetoothDeviceHandle>>().also { mediatorLiveData ->
            mediatorLiveData.value = listBluetoothDevices()
            mediatorLiveData.addSource(isBTHIDAdapterEnabled) { enabled ->
                if (enabled) {
                    mediatorLiveData.value = listBluetoothDevices()
                } else {
                    mediatorLiveData.value = emptyList()
                }
            }
            mediatorLiveData.addSource(deviceHistoryConfigProperty.liveData) { deviceHistory ->
                val deviceList = mediatorLiveData.value
                deviceHistory?.forEach { entry ->
                    deviceList?.firstOrNull { deviceHandle -> deviceHandle.address == entry.address }?.lastConnectedAt =
                        entry.lastConnectedAt
                }
                mediatorLiveData.value =
                    deviceList?.sortedWith(compareBy<BluetoothDeviceHandle> { it.lastConnectedAt }.thenBy { it.name })
                        ?.reversed()
            }
        }
    }

    @RequiresPermission(value = "android.permission.BLUETOOTH_CONNECT")
    private fun listBluetoothDevices(): List<BluetoothDeviceHandle> {
        return if (isBTHIDAdapterEnabled.value!!) {
            (bluetoothAdapter?.bondedDevices ?: emptyList()).filter {
                it.name != null &&
                        it.address != null &&
                        it.type != DEVICE_TYPE_LE &&
                        when (it.bluetoothClass.majorDeviceClass) {
                            Device.Major.COMPUTER -> true
                            Device.Major.AUDIO_VIDEO -> false
                            Device.Major.HEALTH -> false
                            Device.Major.IMAGING -> false
                            Device.Major.MISC -> false
                            Device.Major.NETWORKING -> false
                            Device.Major.PHONE -> true
                            Device.Major.TOY -> false
                            Device.Major.UNCATEGORIZED -> true
                            Device.Major.WEARABLE -> false
                            else -> true
                        }
            }.map {
                val deviceHistoryEntry =
                    deviceHistoryConfigProperty.value?.firstOrNull { deviceHistoryEntry -> deviceHistoryEntry.address == it.address }
                BluetoothDeviceHandle(it.name, it.address, deviceHistoryEntry?.lastConnectedAt)
            }.sortedWith(compareBy<BluetoothDeviceHandle> { it.lastConnectedAt }.thenBy { it.name })
                .reversed()
        } else emptyList()
    }

    private var isBound = false

    private val _isBTHIDAdapterEnabled: Boolean
        get() = isBTHIDAdapterAvailable && bluetoothAdapter?.isEnabled ?: false

    private val unifidoKeyApplication = applicationContext as UnifidoKeyApplicationBase<*>
    private var deviceHistoryConfigProperty =
        unifidoKeyApplication.unifidoKeyComponent.configManager.bthidDeviceHistory
    private val mutableBTHIDAdapterEnabled: MutableLiveData<Boolean> =
        MutableLiveData(_isBTHIDAdapterEnabled)


    override val isBTHIDAdapterAvailable: Boolean
        get() {
            if(ContextCompat.checkSelfPermission(applicationContext, Manifest.permission.BLUETOOTH_CONNECT) != PackageManager.PERMISSION_GRANTED){
                return false
            }
            if (packageManager.hasSystemFeature(PackageManager.FEATURE_BLUETOOTH)) {
                return bluetoothAdapter != null
            }
            return false
        }
    override val isBTHIDAdapterEnabled: LiveData<Boolean>
        get() = mutableBTHIDAdapterEnabled

    init {
        bthidBroadcastReceiver.register(applicationContext)
    }

    override fun close() {
        bthidBroadcastReceiver.unregister(applicationContext) //TODO: この順番で大丈夫か？
    }

    @RequiresPermission(value = "android.permission.BLUETOOTH_CONNECT")
    override fun connect(deviceHandle: BluetoothDeviceHandle) {
        ctapBTHIDAndroidService.let {
            when (it) {
                null -> throw IllegalStateException("Service is not bound.")
                else -> it.connect(deviceHandle)
            }
        }
    }

    @RequiresPermission(value = "android.permission.BLUETOOTH_CONNECT")
    override fun disconnect(deviceHandle: BluetoothDeviceHandle) {
        ctapBTHIDAndroidService.let {
            when (it) {
                null -> throw IllegalStateException("Service is not bound.")
                else -> it.disconnect(deviceHandle)
            }
        }
    }

    fun startForeground() {
        ctapBTHIDAndroidService.let {
            when (it) {
                null -> throw IllegalStateException("Service is not bound.")
                else -> it.startForeground()
            }
        }
    }

    fun stopForeground() {
        ctapBTHIDAndroidService.let {
            when (it) {
                null -> throw IllegalStateException("Service is not bound.")
                else -> it.stopForeground(true)
            }
        }
    }

    fun startForegroundService() {
        val serviceIntent = Intent(applicationContext, CtapBTHIDAndroidService::class.java)
        applicationContext.startForegroundService(serviceIntent)
    }

    fun startService() {
        val serviceIntent = Intent(applicationContext, CtapBTHIDAndroidService::class.java)
        applicationContext.startService(serviceIntent)
    }

    fun stopService() {
        val serviceIntent = Intent(applicationContext, CtapBTHIDAndroidService::class.java)
        applicationContext.stopService(serviceIntent)
    }


    fun bindService(activity: AppCompatActivity) {
        if (ctapBTHIDDroidServiceConnection == null) {
            CtapBTHIDDroidServiceConnection().let {
                ctapBTHIDDroidServiceConnection = it
                val serviceIntent = Intent(applicationContext, CtapBTHIDAndroidService::class.java)
                activity.bindService(serviceIntent, it, Context.BIND_AUTO_CREATE)
                isBound = true
            }
        }
    }

    fun unbindService(activity: AppCompatActivity) {
        if (isBound) {
            activity.unbindService(ctapBTHIDDroidServiceConnection!!)
            isBound = false
        }
    }


    @Suppress("UNCHECKED_CAST")
    internal inner class CtapBTHIDDroidServiceConnection : ServiceConnection {
        override fun onServiceConnected(name: ComponentName, service: IBinder) {
            val binder = service as CtapBTHIDAndroidService.CtapBTHIDAndroidServiceBinder
            ctapBTHIDAndroidService = binder.service
        }

        override fun onServiceDisconnected(name: ComponentName) {
            ctapBTHIDAndroidService = null
        }
    }

    private inner class BTHIDBroadcastReceiver : BroadcastReceiver() {
        private val logger = LoggerFactory.getLogger(BTHIDBroadcastReceiver::class.java)
        private val intentFilter: IntentFilter = IntentFilter().apply {
            addAction(BluetoothAdapter.ACTION_STATE_CHANGED)
            addAction(BluetoothAdapter.ACTION_CONNECTION_STATE_CHANGED)
        }
        private var registered = false

        fun register(context: Context) {
            if (!registered) {
                context.registerReceiver(this, intentFilter)
                registered = true
            }
        }

        fun unregister(context: Context) {
            if (registered) {
                context.unregisterReceiver(this)
                registered = false
            }
        }

        @RequiresPermission(value = "android.permission.BLUETOOTH_CONNECT")
        override fun onReceive(context: Context, intent: Intent) {
            val action = intent.action
            if (action != null) {
                when (action) {

                    BluetoothAdapter.ACTION_STATE_CHANGED -> {
                        val previousState = intent.getIntExtra(
                            BluetoothAdapter.EXTRA_PREVIOUS_STATE,
                            BluetoothAdapter.ERROR
                        )
                        val state = intent.getIntExtra(BluetoothAdapter.EXTRA_STATE, BluetoothAdapter.ERROR)
                        val bluetoothDevice = intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE, BluetoothDevice::class.java)
                        val isBTHIDEnabled = state == BluetoothAdapter.STATE_ON
                        logger.info(
                            "State changed from {} to {}, name: {}",
                            resolveState(previousState),
                            resolveState(state),
                            bluetoothDevice?.name
                        )
                        this@CtapBTHIDAndroidServiceContextualAdapter.mutableBTHIDAdapterEnabled.value =
                            isBTHIDEnabled
                        bluetoothDevices.value?.forEach {
                            it.setConnectionState("disconnected")
                        }
                    }
                    BluetoothAdapter.ACTION_CONNECTION_STATE_CHANGED -> {
                        val previousConnectionState = intent.getIntExtra(
                            BluetoothAdapter.EXTRA_PREVIOUS_CONNECTION_STATE,
                            BluetoothAdapter.ERROR
                        )
                        val connectionState = intent.getIntExtra(
                            BluetoothAdapter.EXTRA_CONNECTION_STATE,
                            BluetoothAdapter.ERROR
                        )
                        val bluetoothDevice = intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE, BluetoothDevice::class.java)
                        logger.info(
                            "connectionState changed from {} to {}, name: {}",
                            resolveConnectionState(previousConnectionState),
                            resolveConnectionState(connectionState),
                            bluetoothDevice?.name
                        )
                        if (bluetoothDevice != null) {
                            val bluetoothDeviceHandle = (bluetoothDevices.value
                                ?: emptyList()).firstOrNull { it.address == bluetoothDevice.address }
                            if (bluetoothDeviceHandle != null) {
                                val resolved = resolveConnectionState(connectionState)
                                bluetoothDeviceHandle.setConnectionState(resolved)
                                val deviceHistory = deviceHistoryConfigProperty.value ?: listOf()
                                val deviceHistoryEntry =
                                    deviceHistory.firstOrNull { entry -> entry.address == bluetoothDevice.address }
                                if (deviceHistoryEntry != null) {
                                    deviceHistoryEntry.lastConnectedAt = Instant.now()
                                    deviceHistoryConfigProperty.value = deviceHistory
                                } else {
                                    val deviceHistoryEntity =
                                        BTHIDDeviceHistoryEntry(
                                            bluetoothDevice.address,
                                            Instant.now()
                                        )
                                    deviceHistoryConfigProperty.value =
                                        mutableListOf<BTHIDDeviceHistoryEntry>().apply {
                                            addAll(deviceHistory)
                                            add(deviceHistoryEntity)
                                        }
                                }
                            }
                        }
                    }
                    else -> throw IllegalStateException()
                }
            }
        }


    }


    private fun resolveState(state: Int): String {
        return when (state) {
            BluetoothAdapter.STATE_OFF -> "OFF"
            BluetoothAdapter.STATE_TURNING_ON -> "TURNING_ON"
            BluetoothAdapter.STATE_ON -> "ON"
            BluetoothAdapter.STATE_TURNING_OFF -> "TURNING_OFF"
            14 -> "BLE_TURNING_ON"
            15 -> "BLE_ON"
            16 -> "BLE_TURNING_OFF"
            BluetoothAdapter.ERROR -> "error"
            else -> throw IllegalStateException()
        }
    }

    private fun resolveConnectionState(state: Int): String {
        return when (state) {
            BluetoothProfile.STATE_DISCONNECTED -> "disconnected"
            BluetoothProfile.STATE_CONNECTING -> "connecting"
            BluetoothProfile.STATE_CONNECTED -> "connected"
            BluetoothProfile.STATE_DISCONNECTING -> "disconnecting"
            BluetoothAdapter.ERROR -> "error"
            else -> throw IllegalStateException()
        }
    }
}