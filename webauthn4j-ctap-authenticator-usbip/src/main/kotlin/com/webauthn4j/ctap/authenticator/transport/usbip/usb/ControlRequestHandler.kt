package com.webauthn4j.ctap.authenticator.transport.usbip.usb

import com.webauthn4j.ctap.authenticator.transport.usbip.USBIPDeviceConfig
import com.webauthn4j.ctap.authenticator.transport.usbip.protocol.SubmitResponse
import com.webauthn4j.ctap.authenticator.transport.usbip.protocol.SubmitRequest
import com.webauthn4j.ctap.authenticator.transport.usbip.protocol.USBIPProtocol
import org.slf4j.LoggerFactory

/**
 * Handles USB control endpoint (EP0) transfers.
 * Processes standard USB requests like GET_DESCRIPTOR, SET_CONFIGURATION, etc.
 */
class ControlRequestHandler(
    private val config: USBIPDeviceConfig
) {
    private val logger = LoggerFactory.getLogger(ControlRequestHandler::class.java)

    fun handle(request: SubmitRequest): SubmitResponse {
        val setup = SetupPacket.parse(request.setup)

        logger.debug("Control request: type=0x{}, req=0x{}, value=0x{}, index=0x{}, length={}",
            Integer.toHexString(setup.bmRequestType),
            Integer.toHexString(setup.bRequest),
            Integer.toHexString(setup.wValue),
            Integer.toHexString(setup.wIndex),
            setup.wLength)

        return when (setup.bRequest) {
            USBConstants.USB_REQ_GET_DESCRIPTOR -> handleGetDescriptor(request, setup)
            USBConstants.USB_REQ_SET_CONFIGURATION -> handleSetConfiguration(request, setup.wValue)
            USBConstants.USB_REQ_SET_IDLE -> handleSetIdle(request)
            else -> {
                logger.warn("Unsupported control request: 0x{}", Integer.toHexString(setup.bRequest))
                SubmitResponse.error(request, USBIPProtocol.STATUS_EPIPE)
            }
        }
    }

    private fun handleGetDescriptor(request: SubmitRequest, setup: SetupPacket): SubmitResponse {
        val descriptorType = (setup.wValue shr 8) and 0xFF
        val descriptorIndex = setup.wValue and 0xFF

        logger.debug("GET_DESCRIPTOR: type=0x{}, index={}, length={}",
            Integer.toHexString(descriptorType), descriptorIndex, setup.wLength)

        val descriptorData = when (descriptorType) {
            USBConstants.USB_DT_DEVICE -> USBDescriptors.generateDeviceDescriptor(config)
            USBConstants.USB_DT_CONFIG -> USBDescriptors.generateConfigurationDescriptor()
            USBConstants.USB_DT_STRING -> USBDescriptors.generateStringDescriptor(descriptorIndex, config.deviceName)
            USBConstants.USB_DT_REPORT -> USBDescriptors.getReportDescriptor()
            USBConstants.USB_DT_HID -> USBDescriptors.getHIDDescriptor()
            else -> {
                logger.warn("Unknown descriptor type: 0x{}", Integer.toHexString(descriptorType))
                return SubmitResponse.error(request, USBIPProtocol.STATUS_EPIPE)
            }
        }

        val responseData = descriptorData.copyOf(minOf(descriptorData.size, setup.wLength))
        logger.debug("Returning {} bytes of descriptor data", responseData.size)
        return SubmitResponse.success(request, responseData)
    }

    private fun handleSetConfiguration(request: SubmitRequest, value: Int): SubmitResponse {
        logger.debug("SET_CONFIGURATION: value={}", value)
        return SubmitResponse.success(request, ByteArray(0))
    }

    private fun handleSetIdle(request: SubmitRequest): SubmitResponse {
        logger.debug("SET_IDLE request")
        return SubmitResponse.success(request, ByteArray(0))
    }
}
