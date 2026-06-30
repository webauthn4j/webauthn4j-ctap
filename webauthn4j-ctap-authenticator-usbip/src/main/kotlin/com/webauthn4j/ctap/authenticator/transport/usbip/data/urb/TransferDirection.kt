package com.webauthn4j.ctap.authenticator.transport.usbip.data.urb

/** USB transfer direction: OUT (host→device) or IN (device→host). */
enum class TransferDirection(val value: Int) {
    OUT(0x00),
    IN(0x01);

    companion object {
        fun fromValue(value: Int): TransferDirection =
            entries.first { it.value == value }
    }
}
