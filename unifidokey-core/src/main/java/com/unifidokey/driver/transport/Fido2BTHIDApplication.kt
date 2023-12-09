package com.unifidokey.driver.transport

import android.Manifest
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothHidDevice
import android.bluetooth.BluetoothProfile
import androidx.annotation.RequiresPermission
import androidx.annotation.WorkerThread
import com.webauthn4j.ctap.authenticator.CtapAuthenticator
import com.webauthn4j.ctap.authenticator.transport.hid.HIDTransport
import com.webauthn4j.ctap.core.util.internal.HexUtil
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.newSingleThreadContext
import org.slf4j.LoggerFactory

class Fido2BTHIDApplication(
    ctapAuthenticator: CtapAuthenticator,
    private val bluetoothHidDevice: BluetoothHidDevice
) : BluetoothHidDevice.Callback() {

    private val logger = LoggerFactory.getLogger(Fido2BTHIDApplication::class.java)

    //single thread worker to synchronize authenticator access
    private val bthidWorker = newSingleThreadContext("bthid-worker")

    private val hidTransport = HIDTransport(ctapAuthenticator)

    @WorkerThread
    @RequiresPermission(Manifest.permission.BLUETOOTH_CONNECT)
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
    @RequiresPermission(Manifest.permission.BLUETOOTH_CONNECT)
    override fun onGetReport(device: BluetoothDevice, type: Byte, id: Byte, bufferSize: Int) {
        super.onGetReport(device, type, id, bufferSize)
        logger.debug("onSetProtocol: device=${device.name}, type=${type}, id=${id}, bufferSize=${bufferSize}")
        bluetoothHidDevice.reportError(device, BluetoothHidDevice.ERROR_RSP_UNSUPPORTED_REQ)
    }

    @WorkerThread
    @RequiresPermission(Manifest.permission.BLUETOOTH_CONNECT)
    override fun onSetReport(device: BluetoothDevice, type: Byte, id: Byte, data: ByteArray?) {
        super.onSetReport(device, type, id, data)
        logger.debug(
            "onSetProtocol: device=${device.name}, type=${type}, id=${id}, data=${
                HexUtil.encodeToString(
                    data
                )
            }"
        )
        bluetoothHidDevice.reportError(device, BluetoothHidDevice.ERROR_RSP_SUCCESS)
    }

    @WorkerThread
    @RequiresPermission(Manifest.permission.BLUETOOTH_CONNECT)
    override fun onSetProtocol(device: BluetoothDevice, protocol: Byte) {
        super.onSetProtocol(device, protocol)
        logger.debug("onSetProtocol: device=${device.name}, protocol=${protocol}")
    }

    @WorkerThread
    @RequiresPermission(Manifest.permission.BLUETOOTH_CONNECT)
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
            hidTransport.onHIDDataReceived(data) { response ->
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