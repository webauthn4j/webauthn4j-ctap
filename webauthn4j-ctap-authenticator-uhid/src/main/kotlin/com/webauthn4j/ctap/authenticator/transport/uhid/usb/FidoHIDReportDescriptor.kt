package com.webauthn4j.ctap.authenticator.transport.uhid.usb

/**
 * Standard FIDO HID report descriptor as defined in the CTAP specification.
 * Registers a FIDO Alliance Usage Page (0xF1D0) device with 64-byte input and output reports.
 */
object FidoHIDReportDescriptor {
    val DESCRIPTOR: ByteArray = byteArrayOf(
        0x06, 0xD0.toByte(), 0xF1.toByte(),   // Usage Page (FIDO Alliance = 0xF1D0)
        0x09, 0x01,                             // Usage (U2F HID Authenticator Device)
        0xA1.toByte(), 0x01,                    // Collection (Application)
        0x09, 0x20,                             //   Usage (Input Report Data)
        0x15, 0x00,                             //   Logical Minimum (0)
        0x26, 0xFF.toByte(), 0x00,              //   Logical Maximum (255)
        0x75, 0x08,                             //   Report Size (8)
        0x95.toByte(), 0x40,                    //   Report Count (64)
        0x81.toByte(), 0x02,                    //   Input (Data, Var, Abs)
        0x09, 0x21,                             //   Usage (Output Report Data)
        0x15, 0x00,                             //   Logical Minimum (0)
        0x26, 0xFF.toByte(), 0x00,              //   Logical Maximum (255)
        0x75, 0x08,                             //   Report Size (8)
        0x95.toByte(), 0x40,                    //   Report Count (64)
        0x91.toByte(), 0x02,                    //   Output (Data, Var, Abs)
        0xC0.toByte()                           // End Collection
    )
}
