package com.webauthn4j.ctap.authenticator.transport.usbip.protocol


/**
 * USB-IP protocol constants.
 * See: https://docs.kernel.org/usb/usbip_protocol.html
 */
object USBIPProtocol {

    const val USBIP_VERSION = 0x0111

    // Handshake opcodes
    const val OP_REQ_DEVLIST = 0x8005
    const val OP_REP_DEVLIST = 0x0005
    const val OP_REQ_IMPORT = 0x8003
    const val OP_REP_IMPORT = 0x0003

    // URB commands
    const val USBIP_CMD_SUBMIT = 0x00000001
    const val USBIP_RET_SUBMIT = 0x00000003
    const val USBIP_CMD_UNLINK = 0x00000002
    const val USBIP_RET_UNLINK = 0x00000004

    // Transfer direction
    const val USBIP_DIR_OUT = 0x00
    const val USBIP_DIR_IN = 0x01

    // USB endpoint
    const val EP0_ADDRESS = 0x00

    // Status codes (Linux errno)
    const val STATUS_SUCCESS = 0
    const val STATUS_EINVAL = -22
    const val STATUS_EPIPE = -32
    const val STATUS_ECONNRESET = -104
}
