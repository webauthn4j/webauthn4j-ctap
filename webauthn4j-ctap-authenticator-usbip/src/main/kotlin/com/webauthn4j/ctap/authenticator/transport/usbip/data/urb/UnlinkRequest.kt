package com.webauthn4j.ctap.authenticator.transport.usbip.data.urb

/** USBIP_CMD_UNLINK — request to cancel a previously submitted URB. */
data class UnlinkRequest(
    override val seqnum: Int,
    val unlinkSeqnum: Int
) : UrbRequest() {
    companion object {
        const val COMMAND = 0x00000002
    }
}
