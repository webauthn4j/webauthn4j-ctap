package com.unifidokey.driver.transport

import android.Manifest
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothManager
import android.content.*
import android.content.pm.PackageManager
import android.os.IBinder
import androidx.annotation.RequiresPermission
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import com.unifidokey.core.adapter.CtapBLEAdapter
import org.slf4j.LoggerFactory


/**
 * An [CtapBLEAdapter] for managing [CtapBLEAndroidService].

 * It is bound to [Context]. Its lifecycle is also linked.
 */
class CtapBLEAndroidServiceContextualAdapter(private val context: Context) : CtapBLEAdapter,
    AutoCloseable {
    private val packageManager = context.packageManager
    private val bluetoothManager =
        context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
    private var ctapBLEAndroidService: CtapBLEAndroidService? = null
    private var ctapBLEAndroidServiceConnection: CtapBLEAndroidServiceConnection? = null
    private val bleBroadcastReceiver = BLEBroadcastReceiver()

    private var isBound = false

    private val mutableIsBLEAdapterEnabled: MutableLiveData<Boolean>

    override val isBLEAdapterAvailable: Boolean
        get() {
            if(ContextCompat.checkSelfPermission(context, Manifest.permission.BLUETOOTH_CONNECT) != PackageManager.PERMISSION_GRANTED){
                return false
            }
            if (!packageManager.hasSystemFeature(PackageManager.FEATURE_BLUETOOTH_LE)) {
                return false
            }
            val bluetoothAdapter = bluetoothManager.adapter
            return bluetoothAdapter != null
        }

    override val isBLEAdapterEnabled: LiveData<Boolean>
        get() = mutableIsBLEAdapterEnabled

    private val _isBLEAdapterEnabled: Boolean
        get() {
            val bluetoothAdapter = bluetoothManager.adapter
            return isBLEAdapterAvailable && bluetoothAdapter.isEnabled && bluetoothAdapter.isMultipleAdvertisementSupported
        }

    init {
//        require(context !is Application) { "context must not be Application. It must be Activity or Service." } //TODO:revisit
        mutableIsBLEAdapterEnabled = MutableLiveData(_isBLEAdapterEnabled)
        bleBroadcastReceiver.registerReceiver(context)
    }

    override fun close() {
        bleBroadcastReceiver.unregisterReceiver(context) //TODO: この順番で大丈夫か？
    }

    override fun startPairing() {
        checkNotNull(ctapBLEAndroidService) { "ctapBLEDroidService is not bound." }
        ctapBLEAndroidService!!.startAdvertise()
    }

    override fun stopPairing() {
        checkNotNull(ctapBLEAndroidService) { "ctapBLEDroidService is not bound." }
        ctapBLEAndroidService!!.stopAdvertise()
    }

    fun bindService(activity: AppCompatActivity) {
        if (ctapBLEAndroidServiceConnection == null) {
            ctapBLEAndroidServiceConnection = CtapBLEAndroidServiceConnection()
            val serviceIntent = Intent(context, CtapBLEAndroidService::class.java)
            activity.bindService(
                serviceIntent,
                ctapBLEAndroidServiceConnection!!,
                Context.BIND_AUTO_CREATE
            )
            isBound = true
        }
    }

    fun unbindService(activity: AppCompatActivity) {
        if (isBound) {
            activity.unbindService(ctapBLEAndroidServiceConnection!!)
            isBound = false
        }
    }

    fun startService() {
        val serviceIntent = Intent(context, CtapBLEAndroidService::class.java)
        context.startService(serviceIntent)
    }

    fun stopService() {
        val serviceIntent = Intent(context, CtapBLEAndroidService::class.java)
        context.stopService(serviceIntent)
    }

    @Suppress("UNCHECKED_CAST")
    internal inner class CtapBLEAndroidServiceConnection : ServiceConnection {
        override fun onServiceConnected(name: ComponentName, service: IBinder) {
            val binder = service as CtapBLEAndroidService.CtapBLEDroidServiceBinder
            ctapBLEAndroidService = binder.service
        }

        override fun onServiceDisconnected(name: ComponentName) {
            ctapBLEAndroidService = null
        }
    }

    private inner class BLEBroadcastReceiver : BroadcastReceiver() {
        private val logger = LoggerFactory.getLogger(BLEBroadcastReceiver::class.java)
        private val intentFilter: IntentFilter = IntentFilter().apply {
            addAction(BluetoothDevice.ACTION_BOND_STATE_CHANGED)
            addAction(BluetoothDevice.ACTION_PAIRING_REQUEST)
            addAction(BluetoothAdapter.ACTION_STATE_CHANGED)
        }
        private var registered = false


        fun registerReceiver(context: Context) {
            if (!registered) {
                context.registerReceiver(this, intentFilter)
                registered = true
            }
        }

        fun unregisterReceiver(context: Context) {
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
                    BluetoothDevice.ACTION_BOND_STATE_CHANGED -> {
                        val previousState = intent.getIntExtra(
                            BluetoothDevice.EXTRA_PREVIOUS_BOND_STATE,
                            BluetoothDevice.ERROR
                        )
                        val state = intent.getIntExtra(
                            BluetoothDevice.EXTRA_BOND_STATE,
                            BluetoothDevice.ERROR
                        )
                        val bluetoothDevice =
                            intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE, BluetoothDevice::class.java)
                        logger.info(
                            "Bond state changed from {} to {}, name: {}",
                            resolveBondState(previousState),
                            resolveBondState(state),
                            bluetoothDevice?.name
                        )
                    }
                    BluetoothDevice.ACTION_PAIRING_REQUEST -> {
                        val pairingVariant = intent.getIntExtra(
                            BluetoothDevice.EXTRA_PAIRING_VARIANT,
                            BluetoothAdapter.ERROR
                        )
                        logger.info(resolvePairingVariant(pairingVariant))
                    }
                    BluetoothAdapter.ACTION_STATE_CHANGED -> {
                        val previousState = intent.getIntExtra(
                            BluetoothAdapter.EXTRA_PREVIOUS_STATE,
                            BluetoothAdapter.ERROR
                        )
                        val state =
                            intent.getIntExtra(BluetoothAdapter.EXTRA_STATE, BluetoothAdapter.ERROR)
                        val bluetoothDevice = intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE, BluetoothDevice::class.java)
                        val isBLEEnabled = state == BluetoothAdapter.STATE_ON
                        logger.info(
                            "State changed from {} to {}, name: {}",
                            resolveState(previousState),
                            resolveState(state),
                            bluetoothDevice?.name
                        )
                        this@CtapBLEAndroidServiceContextualAdapter.mutableIsBLEAdapterEnabled.value =
                            isBLEEnabled
                    }
                    else -> throw IllegalStateException()
                }
            }
        }

        private fun resolvePairingVariant(pairingVariant: Int): String {
            return when (pairingVariant) {
                BluetoothDevice.PAIRING_VARIANT_PIN -> "pin"
                BluetoothDevice.PAIRING_VARIANT_PASSKEY_CONFIRMATION -> "passkey_confirmation"
                else -> throw IllegalStateException()
            }
        }

        private fun resolveBondState(bondState: Int): String {
            return when (bondState) {
                BluetoothDevice.BOND_BONDED -> "bonded"
                BluetoothDevice.BOND_BONDING -> "bonding"
                BluetoothDevice.BOND_NONE -> "none"
                BluetoothDevice.ERROR -> "error"
                else -> throw IllegalStateException()
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


    }


}