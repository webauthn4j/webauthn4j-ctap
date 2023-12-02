package com.unifidokey.driver.transport

import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothGattServer
import android.bluetooth.BluetoothGattServerCallback
import android.bluetooth.BluetoothGattService
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothProfile
import android.content.Context
import com.unifidokey.core.service.AuthenticatorService
import com.webauthn4j.converter.util.ObjectConverter
import com.webauthn4j.ctap.authenticator.exception.BLEDataProcessingException
import com.webauthn4j.ctap.authenticator.transport.ble.BLEConnector
import com.webauthn4j.ctap.core.util.internal.ArrayUtil.toHexString
import com.webauthn4j.util.UnsignedNumberUtil
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import org.slf4j.LoggerFactory
import java.util.UUID
import kotlin.experimental.and

class Fido2BLEGATTServer(
    context: Context,
    bluetoothManager: BluetoothManager,
    authenticatorService: AuthenticatorService,
    objectConverter: ObjectConverter
) {


    companion object {
        // FIDO2 GATT Service
        val FIDO2_GATT_SERVICE_UUID: UUID = UUID.fromString("0000fffd-0000-1000-8000-00805f9b34fb")
        val SOFTWARE_REVISION_STRING_UUID: UUID =
            UUID.fromString("00002A28-0000-1000-8000-00805f9b34fb")
        val FIDO_CONTROL_POINT_UUID: UUID = UUID.fromString("f1d0fff1-deaa-ecee-b42f-c9ba7ed623bb")
        val FIDO_STATUS_UUID: UUID = UUID.fromString("f1d0fff2-deaa-ecee-b42f-c9ba7ed623bb")
        val CLIENT_CHARACTERISTIC_CONFIGURATION_UUID: UUID =
            UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")
        val FIDO_CONTROL_POINT_LENGTH_UUID: UUID =
            UUID.fromString("f1d0fff3-deaa-ecee-b42f-c9ba7ed623bb")
        val FIDO_SERVICE_REVISION_BITFIELD_UUID: UUID =
            UUID.fromString("f1d0fff4-deaa-ecee-b42f-c9ba7ed623bb")

        // Device Information Service
        val DEVICE_INFORMATION_SERVICE_UUID: UUID =
            UUID.fromString("0000180a-0000-1000-8000-00805f9b34fb")
        val MANUFACTURER_NAME_STRING_UUID: UUID =
            UUID.fromString("00002a29-0000-1000-8000-00805f9b34fb")
        val MODEL_NUMBER_STRING_UUID: UUID = UUID.fromString("00002a24-0000-1000-8000-00805f9b34fb")
        val FIRMWARE_REVISION_STRING_UUID: UUID =
            UUID.fromString("00002a26-0000-1000-8000-00805f9b34fb")
        private const val FLAG_FIDO2: Byte = 32
        private const val NOTIFY_OFF: Byte = 0
        private const val NOTIFY_ON: Byte = 1
        private const val FIDO_CONTROL_POINT_LENGTH = 256
    }

    private val logger = LoggerFactory.getLogger(Fido2BLEGATTServer::class.java)
    private val statusCharacteristic = BluetoothGattCharacteristic(
        FIDO_STATUS_UUID,
        BluetoothGattCharacteristic.PROPERTY_NOTIFY,
        BluetoothGattCharacteristic.PERMISSION_READ_ENCRYPTED
    )

    private val fido2GattService = createFido2GattService()
    private val deviceInformationService = createDeviceInformationService()

    private val gattServer: BluetoothGattServer
    private var bluetoothDevice: BluetoothDevice? = null
    private val bleConnector: BLEConnector

    init {
        val callback = GattServerCallbackHandler()
        gattServer = bluetoothManager.openGattServer(context, callback)
        gattServer.addService(deviceInformationService)
        // gattServer.addService(fido2GattService) is not called here, and is called in onServiceAdded
        // as it must be called after previous service(device information service) registration completes.
        bleConnector = BLEConnector(
            authenticatorService.ctapAuthenticator.connect(), //TODO: revisit
            objectConverter
        ) { bytes: ByteArray -> notifyStatusCharacteristicChanged(bytes) }
    }

    private fun notifyStatusCharacteristicChanged(bytes: ByteArray) {
        statusCharacteristic.value = bytes
        gattServer.notifyCharacteristicChanged(bluetoothDevice, statusCharacteristic, true)
    }

    private fun createFido2GattService(): BluetoothGattService {
        val fidoService =
            BluetoothGattService(FIDO2_GATT_SERVICE_UUID, BluetoothGattService.SERVICE_TYPE_PRIMARY)
        val clientCharacteristicConfigurationDescriptor = BluetoothGattDescriptor(
            CLIENT_CHARACTERISTIC_CONFIGURATION_UUID,
            BluetoothGattCharacteristic.PERMISSION_READ or BluetoothGattCharacteristic.PERMISSION_WRITE
        )
        val controlPointCharacteristic = BluetoothGattCharacteristic(
            FIDO_CONTROL_POINT_UUID,
            BluetoothGattCharacteristic.PROPERTY_WRITE or BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE,
            BluetoothGattCharacteristic.PERMISSION_WRITE_ENCRYPTED
        )
        val controlPointLengthCharacteristic = BluetoothGattCharacteristic(
            FIDO_CONTROL_POINT_LENGTH_UUID,
            BluetoothGattCharacteristic.PROPERTY_READ,
            BluetoothGattCharacteristic.PERMISSION_READ_ENCRYPTED
        )
        val serviceRevisionBitfieldCharacteristic = BluetoothGattCharacteristic(
            FIDO_SERVICE_REVISION_BITFIELD_UUID,
            BluetoothGattCharacteristic.PROPERTY_READ or BluetoothGattCharacteristic.PROPERTY_WRITE or BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE,
            BluetoothGattCharacteristic.PERMISSION_READ_ENCRYPTED or BluetoothGattCharacteristic.PERMISSION_WRITE_ENCRYPTED
        )
        fidoService.addCharacteristic(controlPointCharacteristic)
        fidoService.addCharacteristic(statusCharacteristic)
        statusCharacteristic.addDescriptor(clientCharacteristicConfigurationDescriptor)
        fidoService.addCharacteristic(controlPointLengthCharacteristic)
        fidoService.addCharacteristic(serviceRevisionBitfieldCharacteristic)
        return fidoService
    }

    private fun createDeviceInformationService(): BluetoothGattService {
        val deviceInformationService = BluetoothGattService(
            DEVICE_INFORMATION_SERVICE_UUID,
            BluetoothGattService.SERVICE_TYPE_PRIMARY
        )
        val manufacturerNameStringCharacteristic = BluetoothGattCharacteristic(
            MANUFACTURER_NAME_STRING_UUID,
            BluetoothGattCharacteristic.PROPERTY_READ,
            BluetoothGattCharacteristic.PERMISSION_READ_ENCRYPTED
        )
        val modelNumberStringCharacteristic = BluetoothGattCharacteristic(
            MODEL_NUMBER_STRING_UUID,
            BluetoothGattCharacteristic.PROPERTY_READ,
            BluetoothGattCharacteristic.PERMISSION_READ_ENCRYPTED
        )
        val firmwareRevisionStringCharacteristic = BluetoothGattCharacteristic(
            FIRMWARE_REVISION_STRING_UUID,
            BluetoothGattCharacteristic.PROPERTY_READ,
            BluetoothGattCharacteristic.PERMISSION_READ_ENCRYPTED
        )
        deviceInformationService.addCharacteristic(manufacturerNameStringCharacteristic)
        deviceInformationService.addCharacteristic(modelNumberStringCharacteristic)
        deviceInformationService.addCharacteristic(firmwareRevisionStringCharacteristic)
        return deviceInformationService
    }

    private inner class GattServerCallbackHandler : BluetoothGattServerCallback() {
        private val logger = LoggerFactory.getLogger(GattServerCallbackHandler::class.java)
        override fun onServiceAdded(status: Int, service: BluetoothGattService) {
            if (status == BluetoothGatt.GATT_SUCCESS) {
                if (service.uuid == DEVICE_INFORMATION_SERVICE_UUID) {
                    gattServer.addService(fido2GattService)
                }
            } else {
                logger.error("Failed to add GATT service:{}", service.uuid.toString())
            }
        }

        override fun onDescriptorReadRequest(
            device: BluetoothDevice,
            requestId: Int,
            offset: Int,
            descriptor: BluetoothGattDescriptor
        ) {
            super.onDescriptorReadRequest(device, requestId, offset, descriptor)
            val uuid = descriptor.uuid

            // FIDO2 GATT Service
            if (uuid == CLIENT_CHARACTERISTIC_CONFIGURATION_UUID) {
                logger.debug("Client Characteristic Configuration is read")
                val value = UnsignedNumberUtil.toBytes(NOTIFY_OFF.toInt())
                descriptor.value = value
                gattServer.sendResponse(
                    device,
                    requestId,
                    BluetoothGatt.GATT_SUCCESS,
                    offset,
                    value
                )
            } else {
                logger.error("Unsupported Characteristic {} is read", uuid)
                gattServer.sendResponse(
                    device,
                    requestId,
                    BluetoothGatt.GATT_REQUEST_NOT_SUPPORTED,
                    offset,
                    null
                )
            }
        }

        override fun onDescriptorWriteRequest(
            device: BluetoothDevice, requestId: Int,
            descriptor: BluetoothGattDescriptor,
            preparedWrite: Boolean, responseNeeded: Boolean,
            offset: Int, value: ByteArray
        ) {
            super.onDescriptorWriteRequest(
                device,
                requestId,
                descriptor,
                preparedWrite,
                responseNeeded,
                offset,
                value
            )
            if (responseNeeded) {
                gattServer.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, offset, null)
            }
        }

        override fun onCharacteristicWriteRequest(
            device: BluetoothDevice,
            requestId: Int,
            characteristic: BluetoothGattCharacteristic,
            preparedWrite: Boolean,
            responseNeeded: Boolean,
            offset: Int,
            value: ByteArray
        ) {
            super.onCharacteristicWriteRequest(
                device,
                requestId,
                characteristic,
                preparedWrite,
                responseNeeded,
                offset,
                value
            )
            CoroutineScope(Dispatchers.Default).launch {
                logger.debug("GATT received write request:{}", toHexString(value))
                val uuid = characteristic.uuid
                if (uuid == FIDO_CONTROL_POINT_UUID) {
                    logger.debug("FIDO 2.0 Control Point is written")
                    bleConnector.handle(value)
                } else if (uuid == FIDO_SERVICE_REVISION_BITFIELD_UUID) {
                    logger.debug("FIDO 2.0 Service Revision Bitfield is written")
                    if (value.isEmpty()) {
                        throw BLEDataProcessingException("Illegal value is written to FIDO Service Revision Bitfield characteristic.")
                    }
                    val serviceRevisionBitField = value[0]
                    if (serviceRevisionBitField and FLAG_FIDO2 == 0.toByte()) {
                        throw BLEDataProcessingException("FIDO 2.0 is not supported by client.")
                    } else {
                        logger.debug("FIDO 2.0 is requested by client.")
                    }
                } else {
                    logger.error("Unsupported Characteristic {} is written", uuid)
                }
                if (responseNeeded) {
                    gattServer.sendResponse(
                        device,
                        requestId,
                        BluetoothGatt.GATT_SUCCESS,
                        offset,
                        value
                    )
                }
            }
        }

        override fun onCharacteristicReadRequest(
            device: BluetoothDevice,
            requestId: Int,
            offset: Int,
            characteristic: BluetoothGattCharacteristic
        ) {
            super.onCharacteristicReadRequest(device, requestId, offset, characteristic)

            // FIDO2 GATT Service
            when (val uuid = characteristic.uuid) {
                FIDO_CONTROL_POINT_LENGTH_UUID -> {
                    logger.debug("FIDO 2.0 Control Point Length is read")
                    val value = UnsignedNumberUtil.toBytes(FIDO_CONTROL_POINT_LENGTH)
                    gattServer.sendResponse(
                        device,
                        requestId,
                        BluetoothGatt.GATT_SUCCESS,
                        offset,
                        value
                    )
                }
                FIDO_SERVICE_REVISION_BITFIELD_UUID -> {
                    logger.debug("FIDO 2.0 Service Revision Bitfield is read")
                    val value = byteArrayOf(FLAG_FIDO2)
                    gattServer.sendResponse(
                        device,
                        requestId,
                        BluetoothGatt.GATT_SUCCESS,
                        offset,
                        value
                    )
                }
                MANUFACTURER_NAME_STRING_UUID -> {
                    logger.debug("Manufacturer Name String is read")
                    val value = "UnifidoKey".toByteArray()
                    gattServer.sendResponse(
                        device,
                        requestId,
                        BluetoothGatt.GATT_SUCCESS,
                        offset,
                        value
                    )
                }
                MODEL_NUMBER_STRING_UUID -> {
                    logger.debug("Model Number String is read")
                    val value = "1.0".toByteArray()
                    gattServer.sendResponse(
                        device,
                        requestId,
                        BluetoothGatt.GATT_SUCCESS,
                        offset,
                        value
                    )
                }
                FIRMWARE_REVISION_STRING_UUID -> {
                    logger.debug("Firmware Revision String is read")
                    val value = "1.0".toByteArray()
                    gattServer.sendResponse(
                        device,
                        requestId,
                        BluetoothGatt.GATT_SUCCESS,
                        offset,
                        value
                    )
                }
                else -> {
                    logger.error("Unsupported Characteristic {} is read", uuid)
                    gattServer.sendResponse(
                        device,
                        requestId,
                        BluetoothGatt.GATT_REQUEST_NOT_SUPPORTED,
                        offset,
                        null
                    )
                }
            }
        }

        override fun onConnectionStateChange(device: BluetoothDevice, status: Int, newState: Int) {
            super.onConnectionStateChange(device, status, newState)
            when (newState) {
                BluetoothProfile.STATE_CONNECTED -> {
                    logger.info("Central: {} is connected", device.name)
                    bluetoothDevice = device
                }
                BluetoothProfile.STATE_DISCONNECTED -> {
                    logger.info("Central: {} is disconnected", device.name)
                    bluetoothDevice = null
                }
                else -> {
                    logger.info("Unexpected newState {} is provided.", newState)
                }
            }
        }
    }

}