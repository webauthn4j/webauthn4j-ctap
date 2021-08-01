package com.unifidokey.driver.transport

import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothHidDevice
import android.bluetooth.BluetoothProfile
import androidx.annotation.WorkerThread
import com.webauthn4j.converter.util.ObjectConverter
import com.webauthn4j.ctap.authenticator.TransactionManager
import com.webauthn4j.ctap.authenticator.transport.hid.HIDConnector
import com.webauthn4j.ctap.core.util.internal.HexUtil
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.newSingleThreadContext
import org.slf4j.LoggerFactory

class Fido2BTHIDApplication(
    transactionManager: TransactionManager,
    private val bluetoothHidDevice: BluetoothHidDevice,
    objectConverter: ObjectConverter
) : BluetoothHidDevice.Callback() {

    private val logger = LoggerFactory.getLogger(Fido2BTHIDApplication::class.java)

    //single thread worker to synchronize authenticator access
    private val bthidWorker = newSingleThreadContext("bthid-worker")

    private val hidConnector = HIDConnector(transactionManager, objectConverter)

    @WorkerThread
    override fun onAppStatusChanged(pluggedDevice: BluetoothDevice?, registered: Boolean) {
        when (registered) {
            true -> logger.debug(
                "Fido2BTHIDApplication registered, device: {} {}",
                pluggedDevice?.name,
                pluggedDevice?.address
            )
            false -> logger.debug(
                "Fido2BTHIDApplication unregistered, device:  {} {}",
                pluggedDevice?.name,
                pluggedDevice?.address
            )
        }
    }

    @WorkerThread
    override fun onConnectionStateChanged(device: BluetoothDevice, state: Int) {
        when (state) {
            BluetoothProfile.STATE_DISCONNECTED -> logger.debug(
                "Fido2BTHIDApplication disconnected, device: {}",
                device
            )
            BluetoothProfile.STATE_CONNECTING -> logger.debug(
                "Fido2BTHIDApplication connecting, device: {}",
                device
            )
            BluetoothProfile.STATE_CONNECTED -> logger.debug(
                "Fido2BTHIDApplication connected, device: {}",
                device
            )
            BluetoothProfile.STATE_DISCONNECTING -> logger.debug(
                "Fido2BTHIDApplication disconnecting, device: {}",
                device
            )
            else -> logger.debug(
                "Fido2BTHIDApplication transferred to unknown connection state:{}, device: {}",
                state,
                device
            )
        }
    }

    @WorkerThread
    override fun onGetReport(device: BluetoothDevice, type: Byte, id: Byte, bufferSize: Int) {
        super.onGetReport(device, type, id, bufferSize)
        bluetoothHidDevice.reportError(device, BluetoothHidDevice.ERROR_RSP_UNSUPPORTED_REQ)
    }

    @WorkerThread
    override fun onSetReport(device: BluetoothDevice, type: Byte, id: Byte, data: ByteArray?) {
        super.onSetReport(device, type, id, data)
        bluetoothHidDevice.reportError(device, BluetoothHidDevice.ERROR_RSP_SUCCESS)
    }

    @WorkerThread
    override fun onSetProtocol(device: BluetoothDevice, protocol: Byte) {
        super.onSetProtocol(device, protocol)
    }

    @WorkerThread
    override fun onInterruptData(device: BluetoothDevice, reportId: Byte, data: ByteArray?) {
        CoroutineScope(bthidWorker).launch {
            logger.debug(
                "Received report: device=${device.name}, id=${reportId}, data=${
                    HexUtil.encodeToString(
                        data
                    )
                }"
            )
            if (data == null) {
                throw RuntimeException("data must not be null")
            }
            hidConnector.handle(data) { response ->
                CoroutineScope(bthidWorker).launch {
                    val result = bluetoothHidDevice.sendReport(device, reportId.toInt(), response)
                    if (!result) {
                        throw RuntimeException("send failed")
                    }
                    logger.debug(
                        "Sent report: device=${device.name}, id=${reportId}, data=${
                            HexUtil.encodeToString(
                                response
                            )
                        }"
                    )
                }
            }
        }
    }

    @WorkerThread
    override fun onVirtualCableUnplug(device: BluetoothDevice) {
        logger.debug("Fido2BTHIDApplication onUnplugged, device: {}", device)
        super.onVirtualCableUnplug(device)
    }


}