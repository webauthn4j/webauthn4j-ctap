package com.webauthn4j.ctap.authenticator.transport.usbip.data.handshake

/** OP_REQ_IMPORT — requests to attach a remote USB device by bus ID. */
data class ImportRequest(
    override val version: USBIPVersion,
    val busId: String
) : HandshakeRequest() {
    companion object {
        const val OPCODE = 0x8003
    }
}
