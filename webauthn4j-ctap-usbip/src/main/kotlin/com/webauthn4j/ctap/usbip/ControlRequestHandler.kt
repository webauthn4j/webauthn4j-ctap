package com.webauthn4j.ctap.usbip

import org.slf4j.LoggerFactory

/**
 * Handles USB control endpoint (EP0) transfers.
 * Processes standard USB requests like GET_DESCRIPTOR, SET_CONFIGURATION, etc.
 */
class ControlRequestHandler(
    private val config: USBIPDeviceConfig
) {
    private val logger = LoggerFactory.getLogger(ControlRequestHandler::class.java)

    private var configurationSet = false

    /**
     * Handles a control transfer URB.
     */
    fun handle(urb: USBIPProtocol.URBSubmit): USBIPProtocol.URBResult {
        // Parse setup packet (8 bytes)
        val setup = urb.setup
        val bmRequestType = setup[0].toInt() and 0xFF
        val bRequest = setup[1].toInt() and 0xFF
        val wValue = ((setup[3].toInt() and 0xFF) shl 8) or (setup[2].toInt() and 0xFF)
        val wIndex = ((setup[5].toInt() and 0xFF) shl 8) or (setup[4].toInt() and 0xFF)
        val wLength = ((setup[7].toInt() and 0xFF) shl 8) or (setup[6].toInt() and 0xFF)

        logger.debug(
            "Control request: type=0x{}, req=0x{}, value=0x{}, index=0x{}, length={}",
            Integer.toHexString(bmRequestType),
            Integer.toHexString(bRequest),
            Integer.toHexString(wValue),
            Integer.toHexString(wIndex),
            wLength
        )

        return when (bRequest) {
            USBIPProtocol.USB_REQ_GET_DESCRIPTOR -> handleGetDescriptor(urb, wValue, wIndex, wLength)
            USBIPProtocol.USB_REQ_SET_CONFIGURATION -> handleSetConfiguration(urb, wValue)
            USBIPProtocol.USB_REQ_SET_IDLE -> handleSetIdle(urb)
            else -> {
                logger.warn("Unsupported control request: 0x{}", Integer.toHexString(bRequest))
                createStallResult(urb)
            }
        }
    }

    /**
     * Handles GET_DESCRIPTOR request.
     */
    private fun handleGetDescriptor(
        urb: USBIPProtocol.URBSubmit,
        wValue: Int,
        wIndex: Int,
        wLength: Int
    ): USBIPProtocol.URBResult {
        val descriptorType = (wValue shr 8) and 0xFF
        val descriptorIndex = wValue and 0xFF

        logger.debug(
            "GET_DESCRIPTOR: type=0x{}, index={}, length={}",
            Integer.toHexString(descriptorType),
            descriptorIndex,
            wLength
        )

        val descriptorData = when (descriptorType) {
            USBIPProtocol.USB_DT_DEVICE -> {
                logger.debug("Returning device descriptor")
                USBDescriptors.generateDeviceDescriptor(config)
            }
            USBIPProtocol.USB_DT_CONFIG -> {
                logger.debug("Returning configuration descriptor")
                USBDescriptors.generateConfigurationDescriptor()
            }
            USBIPProtocol.USB_DT_STRING -> {
                logger.debug("Returning string descriptor index {}", descriptorIndex)
                USBDescriptors.generateStringDescriptor(descriptorIndex, config.deviceName)
            }
            USBIPProtocol.USB_DT_REPORT -> {
                logger.debug("Returning HID report descriptor")
                USBDescriptors.getReportDescriptor()
            }
            USBIPProtocol.USB_DT_HID -> {
                // HID descriptor is embedded in configuration descriptor
                // Extract it manually (starts at byte 18 in config descriptor)
                logger.debug("Returning HID descriptor (from config)")
                val configDesc = USBDescriptors.generateConfigurationDescriptor()
                configDesc.copyOfRange(18, 27)  // 9 bytes for HID descriptor
            }
            else -> {
                logger.warn("Unknown descriptor type: 0x{}", Integer.toHexString(descriptorType))
                return createStallResult(urb)
            }
        }

        // Truncate to requested length
        val responseData = descriptorData.copyOf(minOf(descriptorData.size, wLength))

        logger.debug("Returning {} bytes of descriptor data", responseData.size)
        return createSuccessResult(urb, responseData)
    }

    /**
     * Handles SET_CONFIGURATION request.
     */
    private fun handleSetConfiguration(urb: USBIPProtocol.URBSubmit, value: Int): USBIPProtocol.URBResult {
        logger.debug("SET_CONFIGURATION: value={}", value)
        configurationSet = (value == 1)
        return createSuccessResult(urb, ByteArray(0))
    }

    /**
     * Handles HID SET_IDLE request.
     */
    private fun handleSetIdle(urb: USBIPProtocol.URBSubmit): USBIPProtocol.URBResult {
        logger.debug("SET_IDLE request")
        return createSuccessResult(urb, ByteArray(0))
    }

    /**
     * Creates a successful URB result.
     */
    private fun createSuccessResult(urb: USBIPProtocol.URBSubmit, data: ByteArray): USBIPProtocol.URBResult {
        return USBIPProtocol.URBResult(
            seqnum = urb.seqnum,
            devid = urb.devid,
            direction = urb.direction,
            ep = urb.ep,
            status = USBIPProtocol.STATUS_SUCCESS,
            actualLength = data.size,
            startFrame = 0,
            numberOfPackets = urb.numberOfPackets,
            errorCount = 0,
            data = data
        )
    }

    /**
     * Creates a STALL result for unsupported requests.
     */
    private fun createStallResult(urb: USBIPProtocol.URBSubmit): USBIPProtocol.URBResult {
        return USBIPProtocol.URBResult(
            seqnum = urb.seqnum,
            devid = urb.devid,
            direction = urb.direction,
            ep = urb.ep,
            status = USBIPProtocol.STATUS_EPIPE,
            actualLength = 0,
            startFrame = 0,
            numberOfPackets = 0,
            errorCount = 0,
            data = ByteArray(0)
        )
    }
}
