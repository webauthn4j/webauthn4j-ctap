package com.webauthn4j.ctap.authenticator.transport.usbip

/**
 * Configuration for USB-IP virtual device.
 *
 * @property deviceName Human-readable device name (manufacturer + product name)
 * @property vendorId USB Vendor ID (0x0000-0xFFFF)
 * @property productId USB Product ID (0x0000-0xFFFF)
 * @property version Device version in BCD format (e.g., 0x0100 for v1.0)
 * @property host Host address to bind the USB-IP server (0.0.0.0 for all interfaces)
 * @property port TCP port for USB-IP protocol (standard is 3240)
 * @property busId Bus ID string for USB-IP device identification (e.g., "1-1")
 * @property busNum USB bus number
 * @property devNum USB device number on the bus
 */
data class USBIPDeviceConfig(
    val deviceName: String = "WebAuthn4J Virtual FIDO2 Key",
    val vendorId: Int = 0x1234,
    val productId: Int = 0xF1D0,
    val version: Int = 0x0100,
    val host: String = "0.0.0.0",
    val port: Int = 3240,
    val busId: String = "1-1",
    val busNum: Int = 1,
    val devNum: Int = 2
) {
    init {
        require(vendorId in 0x0000..0xFFFF) { "Vendor ID must be 0x0000-0xFFFF" }
        require(productId in 0x0000..0xFFFF) { "Product ID must be 0x0000-0xFFFF" }
        require(version in 0x0000..0xFFFF) { "Version must be 0x0000-0xFFFF" }
        require(port in 1..65535) { "Port must be 1-65535" }
        require(busNum >= 0) { "Bus number must be non-negative" }
        require(devNum >= 0) { "Device number must be non-negative" }
        require(busId.isNotBlank()) { "Bus ID must not be blank" }
    }
}
