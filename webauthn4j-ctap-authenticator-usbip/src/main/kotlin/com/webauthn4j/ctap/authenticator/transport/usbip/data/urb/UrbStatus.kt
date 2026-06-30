package com.webauthn4j.ctap.authenticator.transport.usbip.data.urb

/** URB completion status codes (Linux errno values). */
enum class UrbStatus(val value: Int) {
    SUCCESS(0),
    EINVAL(-22),
    EPIPE(-32),
    ECONNRESET(-104);
}
