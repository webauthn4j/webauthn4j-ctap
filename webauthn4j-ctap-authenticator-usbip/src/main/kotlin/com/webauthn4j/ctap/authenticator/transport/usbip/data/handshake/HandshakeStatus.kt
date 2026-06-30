package com.webauthn4j.ctap.authenticator.transport.usbip.data.handshake

/** USB-IP handshake response status. */
enum class HandshakeStatus(val value: Int) {
    OK(0),
    ERROR(1);
}
