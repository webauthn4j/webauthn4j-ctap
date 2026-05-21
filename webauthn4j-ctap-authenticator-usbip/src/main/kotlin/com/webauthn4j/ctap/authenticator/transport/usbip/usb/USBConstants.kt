package com.webauthn4j.ctap.authenticator.transport.usbip.usb

/**
 * Standard USB constants (request codes, descriptor types).
 */
object USBConstants {

    // Standard USB request codes
    const val USB_REQ_GET_DESCRIPTOR = 0x06
    const val USB_REQ_SET_CONFIGURATION = 0x09
    const val USB_REQ_SET_IDLE = 0x0A

    // Descriptor types
    const val USB_DT_DEVICE = 0x01
    const val USB_DT_CONFIG = 0x02
    const val USB_DT_STRING = 0x03
    const val USB_DT_HID = 0x21
    const val USB_DT_REPORT = 0x22
}
