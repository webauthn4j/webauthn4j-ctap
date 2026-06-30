package com.webauthn4j.ctap.authenticator.transport.usbip.endpoint

import com.webauthn4j.ctap.authenticator.transport.usbip.USBIPDeviceConfig

/**
 * USB descriptor generator for a FIDO HID device.
 * Produces device, configuration, HID, report, and string descriptors
 * used by [ControlEndpoint] to respond to GET_DESCRIPTOR requests.
 */
object USBDescriptors {

    /**
     * Standard FIDO HID report descriptor (34 bytes).
     * Defines 64-byte input and output reports for FIDO Alliance Usage Page (0xF1D0).
     */
    private val FIDO_HID_REPORT_DESCRIPTOR = byteArrayOf(
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

    /**
     * Generates USB device descriptor (18 bytes).
     * Describes basic device properties like VID/PID and USB version.
     */
    fun generateDeviceDescriptor(config: USBIPDeviceConfig): ByteArray {
        return byteArrayOf(
            0x12,                                // bLength (18 bytes)
            0x01,                                // bDescriptorType (Device)
            0x00, 0x02,                          // bcdUSB (USB 2.0)
            0x00,                                // bDeviceClass (defined in interface)
            0x00,                                // bDeviceSubClass
            0x00,                                // bDeviceProtocol
            0x40,                                // bMaxPacketSize0 (64 bytes)
            (config.vendorId and 0xFF).toByte(),
            ((config.vendorId shr 8) and 0xFF).toByte(),
            (config.productId and 0xFF).toByte(),
            ((config.productId shr 8) and 0xFF).toByte(),
            (config.version and 0xFF).toByte(),
            ((config.version shr 8) and 0xFF).toByte(),
            0x01,                                // iManufacturer (string index 1)
            0x02,                                // iProduct (string index 2)
            0x00,                                // iSerialNumber (none)
            0x01                                 // bNumConfigurations
        )
    }

    /**
     * Generates complete configuration descriptor tree (41 bytes).
     * Includes: Configuration + Interface + HID + 2 Endpoints (IN + OUT).
     */
    fun generateConfigurationDescriptor(): ByteArray {
        val totalLength = 9 + 9 + 9 + 7 + 7  // Config + Interface + HID + EP_IN + EP_OUT = 41

        return byteArrayOf(
            // Configuration Descriptor (9 bytes)
            0x09,                                // bLength
            0x02,                                // bDescriptorType (Configuration)
            (totalLength and 0xFF).toByte(),
            ((totalLength shr 8) and 0xFF).toByte(),  // wTotalLength
            0x01,                                // bNumInterfaces
            0x01,                                // bConfigurationValue
            0x00,                                // iConfiguration
            0xA0.toByte(),                       // bmAttributes (Bus powered, Remote wakeup)
            0x32,                                // bMaxPower (100mA)

            // Interface Descriptor (9 bytes)
            0x09,                                // bLength
            0x04,                                // bDescriptorType (Interface)
            0x00,                                // bInterfaceNumber
            0x00,                                // bAlternateSetting
            0x02,                                // bNumEndpoints (IN + OUT)
            0x03,                                // bInterfaceClass (HID)
            0x00,                                // bInterfaceSubClass
            0x00,                                // bInterfaceProtocol
            0x00,                                // iInterface

            // HID Descriptor (9 bytes)
            0x09,                                // bLength
            0x21,                                // bDescriptorType (HID)
            0x11, 0x01,                          // bcdHID (HID 1.11)
            0x00,                                // bCountryCode
            0x01,                                // bNumDescriptors
            0x22,                                // bDescriptorType (Report)
            (FIDO_HID_REPORT_DESCRIPTOR.size and 0xFF).toByte(),
            ((FIDO_HID_REPORT_DESCRIPTOR.size shr 8) and 0xFF).toByte(),

            // Endpoint Descriptor - Interrupt IN (7 bytes)
            0x07,                                // bLength
            0x05,                                // bDescriptorType (Endpoint)
            0x81.toByte(),                       // bEndpointAddress (IN, EP1)
            0x03,                                // bmAttributes (Interrupt)
            0x40, 0x00,                          // wMaxPacketSize (64 bytes)
            0x05,                                // bInterval (5ms)

            // Endpoint Descriptor - Interrupt OUT (7 bytes)
            0x07,                                // bLength
            0x05,                                // bDescriptorType (Endpoint)
            0x01,                                // bEndpointAddress (OUT, EP1)
            0x03,                                // bmAttributes (Interrupt)
            0x40, 0x00,                          // wMaxPacketSize (64 bytes)
            0x05                                 // bInterval (5ms)
        )
    }

    /**
     * Returns the FIDO HID report descriptor.
     */
    fun getReportDescriptor(): ByteArray {
        return FIDO_HID_REPORT_DESCRIPTOR
    }

    /**
     * Returns the 9-byte HID class descriptor.
     */
    fun getHIDDescriptor(): ByteArray {
        return byteArrayOf(
            0x09,                                // bLength
            0x21,                                // bDescriptorType (HID)
            0x11, 0x01,                          // bcdHID (HID 1.11)
            0x00,                                // bCountryCode
            0x01,                                // bNumDescriptors
            0x22,                                // bDescriptorType (Report)
            (FIDO_HID_REPORT_DESCRIPTOR.size and 0xFF).toByte(),
            ((FIDO_HID_REPORT_DESCRIPTOR.size shr 8) and 0xFF).toByte()
        )
    }

    /**
     * Generates USB string descriptor.
     * @param index String descriptor index (0 = language IDs, 1 = manufacturer, 2 = product)
     * @param value String value (used for product name from config)
     */
    fun generateStringDescriptor(index: Int, value: String = ""): ByteArray {
        return when (index) {
            0 -> byteArrayOf(
                0x04,                            // bLength
                0x03,                            // bDescriptorType (String)
                0x09, 0x04                       // Language ID: English (US) = 0x0409
            )
            1 -> encodeStringDescriptor("WebAuthn4J")
            2 -> encodeStringDescriptor(value)
            else -> byteArrayOf(0x02, 0x03)      // Empty string
        }
    }

    /**
     * Encodes a string as UTF-16LE for USB string descriptor.
     */
    private fun encodeStringDescriptor(str: String): ByteArray {
        val utf16 = str.toByteArray(Charsets.UTF_16LE)
        return byteArrayOf(
            (utf16.size + 2).toByte(),           // bLength
            0x03                                  // bDescriptorType (String)
        ) + utf16
    }
}
