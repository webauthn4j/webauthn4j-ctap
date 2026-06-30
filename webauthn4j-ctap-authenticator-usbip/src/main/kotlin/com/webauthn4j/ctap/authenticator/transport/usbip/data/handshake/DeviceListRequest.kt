package com.webauthn4j.ctap.authenticator.transport.usbip.data.handshake

/** OP_REQ_DEVLIST — requests the server to list exported USB devices. */
data class DeviceListRequest(
    override val version: USBIPVersion
) : HandshakeRequest() {
    companion object {
        const val OPCODE = 0x8005
    }
}
