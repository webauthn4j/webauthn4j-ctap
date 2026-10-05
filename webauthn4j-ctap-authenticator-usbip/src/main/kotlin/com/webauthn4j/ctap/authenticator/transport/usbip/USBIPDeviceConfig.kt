package com.webauthn4j.ctap.authenticator.transport.usbip

/**
 * USB identity and descriptors for a virtual device. Listener settings belong to USBIPServer.
 *
 * @property deviceName Human-readable device name (manufacturer + product name)
 * @property vendorId USB Vendor ID (0x0000-0xFFFF)
 * @property productId USB Product ID (0x0000-0xFFFF)
 * @property version Device version in BCD format (e.g., 0x0100 for v1.0)
 * @property busId Bus ID string for USB-IP device identification (e.g., "1-1")
 * @property busNum USB bus number
 * @property devNum USB device number on the bus
 */
data class USBIPDeviceConfig(
    val deviceName: String = "WebAuthn4J Virtual FIDO2 Key",
    val vendorId: Int = 0x1234,
    val productId: Int = 0xF1D0,
    val version: Int = 0x0100,
    val busId: String = "1-1",
    val busNum: Int = 1,
    val devNum: Int = 1
) {
    init {
        require(vendorId in 0x0000..0xFFFF) { "Vendor ID must be 0x0000-0xFFFF" }
        require(productId in 0x0000..0xFFFF) { "Product ID must be 0x0000-0xFFFF" }
        require(version in 0x0000..0xFFFF) { "Version must be 0x0000-0xFFFF" }
        require(busNum in 1..65535) { "Bus number must be 1-65535" }
        require(devNum in 1..65535) { "Device number must be 1-65535" }
        require(busId.matches(Regex("[0-9]+-[0-9]+(\\.[0-9]+)*")) && busId.length < 32) { "Invalid USB bus ID" }
    }
}
