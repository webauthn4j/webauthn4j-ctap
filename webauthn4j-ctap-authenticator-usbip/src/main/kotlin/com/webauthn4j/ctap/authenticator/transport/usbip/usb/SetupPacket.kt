package com.webauthn4j.ctap.authenticator.transport.usbip.usb

/**
 * Parsed USB setup packet (8 bytes) from a control transfer.
 */
data class SetupPacket(
    val bmRequestType: Int,
    val bRequest: Int,
    val wValue: Int,
    val wIndex: Int,
    val wLength: Int
) {
    companion object {
        fun parse(setup: ByteArray): SetupPacket = SetupPacket(
            bmRequestType = setup[0].toInt() and 0xFF,
            bRequest = setup[1].toInt() and 0xFF,
            wValue = ((setup[3].toInt() and 0xFF) shl 8) or (setup[2].toInt() and 0xFF),
            wIndex = ((setup[5].toInt() and 0xFF) shl 8) or (setup[4].toInt() and 0xFF),
            wLength = ((setup[7].toInt() and 0xFF) shl 8) or (setup[6].toInt() and 0xFF)
        )
    }
}
