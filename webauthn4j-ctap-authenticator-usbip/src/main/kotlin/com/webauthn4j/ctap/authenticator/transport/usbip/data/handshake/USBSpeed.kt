package com.webauthn4j.ctap.authenticator.transport.usbip.data.handshake

/** USB device speed as reported in USB-IP device descriptors. */
enum class USBSpeed(val value: Int) {
    LOW(1),
    FULL(2),
    HIGH(3),
    WIRELESS(4),
    SUPER(5),
    SUPER_PLUS(6);

    companion object {
        fun fromValue(value: Int): USBSpeed =
            entries.first { it.value == value }
    }
}
