package com.webauthn4j.ctap.authenticator.transport.uhid

data class UHIDDeviceConfig(
    val deviceName: String = "WebAuthn4J Virtual FIDO2 Key",
    val vendorId: Int = 0x1234,
    val productId: Int = 0xF1D0,
    val version: Int = 0x0100,
    val devicePath: String = "/dev/uhid",
    val physicalAddress: String = "",
    val uniqueId: String = ""
)
