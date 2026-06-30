package com.webauthn4j.ctap.authenticator.transport.usbip.endpoint

import com.webauthn4j.ctap.authenticator.transport.usbip.USBIPDeviceConfig
import com.webauthn4j.ctap.authenticator.transport.usbip.data.urb.SubmitRequest
import com.webauthn4j.ctap.authenticator.transport.usbip.data.urb.UrbStatus
import com.webauthn4j.ctap.authenticator.transport.usbip.data.urb.SubmitResponse
import org.slf4j.LoggerFactory

/**
 * USB control endpoint (EP0) emulation.
 * Responds to standard USB requests: GET_DESCRIPTOR, SET_CONFIGURATION, SET_IDLE.
 */
class ControlEndpoint(
    private val config: USBIPDeviceConfig
) {
    private val logger = LoggerFactory.getLogger(ControlEndpoint::class.java)

    companion object {
        const val EP_NUMBER = 0x00

        private const val USB_REQ_GET_DESCRIPTOR = 0x06
        private const val USB_REQ_SET_CONFIGURATION = 0x09
        private const val USB_REQ_SET_IDLE = 0x0A

        private const val USB_DT_DEVICE = 0x01
        private const val USB_DT_CONFIG = 0x02
        private const val USB_DT_STRING = 0x03
        private const val USB_DT_HID = 0x21
        private const val USB_DT_REPORT = 0x22
    }

    fun process(request: SubmitRequest): SubmitResponse {
        val setup = request.setup

        logger.debug("Control request: type=0x{}, req=0x{}, value=0x{}, index=0x{}, length={}",
            Integer.toHexString(setup.bmRequestType),
            Integer.toHexString(setup.bRequest),
            Integer.toHexString(setup.wValue),
            Integer.toHexString(setup.wIndex),
            setup.wLength)

        return when (setup.bRequest) {
            USB_REQ_GET_DESCRIPTOR -> processGetDescriptor(request, setup)
            USB_REQ_SET_CONFIGURATION -> processSetConfiguration(request, setup.wValue)
            USB_REQ_SET_IDLE -> processSetIdle(request)
            else -> {
                logger.warn("Unsupported control request: 0x{}", Integer.toHexString(setup.bRequest))
                SubmitResponse.error(request, UrbStatus.EPIPE)
            }
        }
    }

    private fun processGetDescriptor(request: SubmitRequest, setup: SubmitRequest.Setup): SubmitResponse {
        val descriptorType = (setup.wValue shr 8) and 0xFF
        val descriptorIndex = setup.wValue and 0xFF

        logger.debug("GET_DESCRIPTOR: type=0x{}, index={}, length={}",
            Integer.toHexString(descriptorType), descriptorIndex, setup.wLength)

        val descriptorData = when (descriptorType) {
            USB_DT_DEVICE -> USBDescriptors.generateDeviceDescriptor(config)
            USB_DT_CONFIG -> USBDescriptors.generateConfigurationDescriptor()
            USB_DT_STRING -> USBDescriptors.generateStringDescriptor(descriptorIndex, config.deviceName)
            USB_DT_REPORT -> USBDescriptors.getReportDescriptor()
            USB_DT_HID -> USBDescriptors.getHIDDescriptor()
            else -> {
                logger.warn("Unknown descriptor type: 0x{}", Integer.toHexString(descriptorType))
                return SubmitResponse.error(request, UrbStatus.EPIPE)
            }
        }

        val responseData = descriptorData.copyOf(minOf(descriptorData.size, setup.wLength))
        logger.debug("Returning {} bytes of descriptor data", responseData.size)
        return SubmitResponse.ok(request, responseData)
    }

    private fun processSetConfiguration(request: SubmitRequest, value: Int): SubmitResponse {
        logger.debug("SET_CONFIGURATION: value={}", value)
        return SubmitResponse.ok(request, ByteArray(0))
    }

    private fun processSetIdle(request: SubmitRequest): SubmitResponse {
        logger.debug("SET_IDLE request")
        return SubmitResponse.ok(request, ByteArray(0))
    }
}
