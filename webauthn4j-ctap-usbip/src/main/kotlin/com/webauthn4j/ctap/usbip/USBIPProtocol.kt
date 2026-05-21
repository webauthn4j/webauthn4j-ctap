package com.webauthn4j.ctap.usbip

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * USB-IP protocol implementation following the Linux kernel specification.
 * See: https://docs.kernel.org/usb/usbip_protocol.html
 */
object USBIPProtocol {

    // Protocol version
    const val USBIP_VERSION = 0x0111

    // Operation codes
    const val OP_REQ_DEVLIST = 0x8005
    const val OP_REP_DEVLIST = 0x0005
    const val OP_REQ_IMPORT = 0x8003
    const val OP_REP_IMPORT = 0x0003

    // Command codes
    const val USBIP_CMD_SUBMIT = 0x00000001
    const val USBIP_RET_SUBMIT = 0x00000003
    const val USBIP_CMD_UNLINK = 0x00000002
    const val USBIP_RET_UNLINK = 0x00000004

    // Transfer direction
    const val USBIP_DIR_OUT = 0x00
    const val USBIP_DIR_IN = 0x01

    // USB endpoint addresses
    const val EP0_ADDRESS = 0x00          // Control endpoint
    const val EP_INTERRUPT_OUT = 0x01     // Interrupt OUT
    const val EP_INTERRUPT_IN = 0x81      // Interrupt IN (0x80 | 0x01)

    // Standard USB request codes
    const val USB_REQ_GET_DESCRIPTOR = 0x06
    const val USB_REQ_SET_CONFIGURATION = 0x09
    const val USB_REQ_SET_IDLE = 0x0A

    // Descriptor types
    const val USB_DT_DEVICE = 0x01
    const val USB_DT_CONFIG = 0x02
    const val USB_DT_STRING = 0x03
    const val USB_DT_INTERFACE = 0x04
    const val USB_DT_ENDPOINT = 0x05
    const val USB_DT_HID = 0x21
    const val USB_DT_REPORT = 0x22

    // USB status codes (Linux errno values)
    const val STATUS_SUCCESS = 0
    const val STATUS_EAGAIN = -11         // NAK, no data ready
    const val STATUS_EINVAL = -22         // Invalid request
    const val STATUS_EPIPE = -32          // STALL

    /**
     * Device information structure for USB-IP.
     */
    data class DeviceInfo(
        val path: String,
        val busid: String,
        val busnum: Int,
        val devnum: Int,
        val speed: Int,
        val idVendor: Int,
        val idProduct: Int,
        val bcdDevice: Int,
        val bDeviceClass: Int,
        val bDeviceSubClass: Int,
        val bDeviceProtocol: Int,
        val bConfigurationValue: Int,
        val bNumConfigurations: Int,
        val bNumInterfaces: Int
    )

    /**
     * USB Request Block (URB) for submit command.
     */
    data class URBSubmit(
        val seqnum: Int,
        val devid: Int,
        val direction: Int,
        val ep: Int,
        val transferFlags: Int,
        val transferBufferLength: Int,
        val startFrame: Int,
        val numberOfPackets: Int,
        val interval: Int,
        val setup: ByteArray,
        val data: ByteArray
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false
            other as URBSubmit
            return seqnum == other.seqnum && devid == other.devid && direction == other.direction &&
                    ep == other.ep && transferFlags == other.transferFlags &&
                    transferBufferLength == other.transferBufferLength &&
                    startFrame == other.startFrame && numberOfPackets == other.numberOfPackets &&
                    interval == other.interval && setup.contentEquals(other.setup) &&
                    data.contentEquals(other.data)
        }

        override fun hashCode(): Int {
            var result = seqnum
            result = 31 * result + devid
            result = 31 * result + direction
            result = 31 * result + ep
            result = 31 * result + transferFlags
            result = 31 * result + transferBufferLength
            result = 31 * result + startFrame
            result = 31 * result + numberOfPackets
            result = 31 * result + interval
            result = 31 * result + setup.contentHashCode()
            result = 31 * result + data.contentHashCode()
            return result
        }
    }

    /**
     * URB result for submit return.
     */
    data class URBResult(
        val seqnum: Int,
        val devid: Int,
        val direction: Int,
        val ep: Int,
        val status: Int,
        val actualLength: Int,
        val startFrame: Int,
        val numberOfPackets: Int,
        val errorCount: Int,
        val data: ByteArray
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false
            other as URBResult
            return seqnum == other.seqnum && devid == other.devid && direction == other.direction &&
                    ep == other.ep && status == other.status && actualLength == other.actualLength &&
                    startFrame == other.startFrame && numberOfPackets == other.numberOfPackets &&
                    errorCount == other.errorCount && data.contentEquals(other.data)
        }

        override fun hashCode(): Int {
            var result = seqnum
            result = 31 * result + devid
            result = 31 * result + direction
            result = 31 * result + ep
            result = 31 * result + status
            result = 31 * result + actualLength
            result = 31 * result + startFrame
            result = 31 * result + numberOfPackets
            result = 31 * result + errorCount
            result = 31 * result + data.contentHashCode()
            return result
        }
    }

    /**
     * Serializes OP_REP_DEVLIST response.
     */
    fun serializeOpRepDevlist(devices: List<DeviceInfo>): ByteArray {
        val buffer = ByteBuffer.allocate(8 + devices.size * 312)
        buffer.order(ByteOrder.BIG_ENDIAN)

        // Header
        buffer.putShort(USBIP_VERSION.toShort())
        buffer.putShort(OP_REP_DEVLIST.toShort())
        buffer.putInt(0)  // Status (success)

        // Number of devices
        buffer.putInt(devices.size)

        // Device entries
        for (device in devices) {
            writeString(buffer, device.path, 256)
            writeString(buffer, device.busid, 32)
            buffer.putInt(device.busnum)
            buffer.putInt(device.devnum)
            buffer.putInt(device.speed)
            buffer.putShort(device.idVendor.toShort())
            buffer.putShort(device.idProduct.toShort())
            buffer.putShort(device.bcdDevice.toShort())
            buffer.put(device.bDeviceClass.toByte())
            buffer.put(device.bDeviceSubClass.toByte())
            buffer.put(device.bDeviceProtocol.toByte())
            buffer.put(device.bConfigurationValue.toByte())
            buffer.put(device.bNumConfigurations.toByte())
            buffer.put(device.bNumInterfaces.toByte())
        }

        return buffer.array()
    }

    /**
     * Parses OP_REQ_IMPORT request and returns requested busid.
     */
    fun parseOpReqImport(buffer: ByteBuffer): String {
        buffer.order(ByteOrder.BIG_ENDIAN)
        // Skip header (8 bytes already read)
        return readString(buffer, 32)
    }

    /**
     * Serializes OP_REP_IMPORT response.
     */
    fun serializeOpRepImport(device: DeviceInfo): ByteArray {
        val buffer = ByteBuffer.allocate(320)
        buffer.order(ByteOrder.BIG_ENDIAN)

        // Header
        buffer.putShort(USBIP_VERSION.toShort())
        buffer.putShort(OP_REP_IMPORT.toShort())
        buffer.putInt(0)  // Status (success)

        // Device info
        writeString(buffer, device.path, 256)
        writeString(buffer, device.busid, 32)
        buffer.putInt(device.busnum)
        buffer.putInt(device.devnum)
        buffer.putInt(device.speed)
        buffer.putShort(device.idVendor.toShort())
        buffer.putShort(device.idProduct.toShort())
        buffer.putShort(device.bcdDevice.toShort())
        buffer.put(device.bDeviceClass.toByte())
        buffer.put(device.bDeviceSubClass.toByte())
        buffer.put(device.bDeviceProtocol.toByte())
        buffer.put(device.bConfigurationValue.toByte())
        buffer.put(device.bNumConfigurations.toByte())
        buffer.put(device.bNumInterfaces.toByte())

        return buffer.array()
    }

    /**
     * Parses USBIP_CMD_SUBMIT command.
     */
    fun parseCmdSubmit(buffer: ByteBuffer): URBSubmit {
        buffer.order(ByteOrder.BIG_ENDIAN)

        // Command header (already read: 4 bytes for command code)
        val seqnum = buffer.int
        val devid = buffer.int
        val direction = buffer.int
        val ep = buffer.int

        // Transfer info
        val transferFlags = buffer.int
        val transferBufferLength = buffer.int
        val startFrame = buffer.int
        val numberOfPackets = buffer.int
        val interval = buffer.int

        // Setup packet (8 bytes for control transfers)
        val setup = ByteArray(8)
        buffer.get(setup)

        return URBSubmit(
            seqnum = seqnum,
            devid = devid,
            direction = direction,
            ep = ep,
            transferFlags = transferFlags,
            transferBufferLength = transferBufferLength,
            startFrame = startFrame,
            numberOfPackets = numberOfPackets,
            interval = interval,
            setup = setup,
            data = ByteArray(0)  // Data read separately
        )
    }

    /**
     * Serializes USBIP_RET_SUBMIT response.
     */
    fun serializeRetSubmit(result: URBResult): ByteArray {
        val totalSize = 48 + result.data.size
        val buffer = ByteBuffer.allocate(totalSize)
        buffer.order(ByteOrder.BIG_ENDIAN)

        // Command header
        buffer.putInt(USBIP_RET_SUBMIT)
        buffer.putInt(result.seqnum)
        buffer.putInt(result.devid)
        buffer.putInt(result.direction)
        buffer.putInt(result.ep)

        // Result info
        buffer.putInt(result.status)
        buffer.putInt(result.actualLength)
        buffer.putInt(result.startFrame)
        buffer.putInt(result.numberOfPackets)
        buffer.putInt(result.errorCount)

        // Setup padding (8 bytes)
        buffer.putLong(0)

        // Data
        buffer.put(result.data)

        return buffer.array()
    }

    /**
     * Writes a fixed-length string to the buffer, null-padded.
     */
    private fun writeString(buffer: ByteBuffer, str: String, length: Int) {
        val bytes = str.toByteArray(Charsets.US_ASCII)
        val toCopy = minOf(bytes.size, length - 1)
        buffer.put(bytes, 0, toCopy)
        // Null-pad the rest
        repeat(length - toCopy) {
            buffer.put(0)
        }
    }

    /**
     * Reads a fixed-length null-terminated string from the buffer.
     */
    private fun readString(buffer: ByteBuffer, length: Int): String {
        val bytes = ByteArray(length)
        buffer.get(bytes)
        // Find null terminator
        val nullIndex = bytes.indexOf(0)
        val endIndex = if (nullIndex >= 0) nullIndex else bytes.size
        return String(bytes, 0, endIndex, Charsets.US_ASCII)
    }
}
