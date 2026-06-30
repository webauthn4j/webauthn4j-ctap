package com.webauthn4j.ctap.authenticator.transport.usbip.data.urb

/** USBIP_CMD_SUBMIT — a USB Request Block submitted by the client. */
class SubmitRequest(
    override val seqnum: Int,
    val devid: Int,
    val direction: TransferDirection,
    val ep: Int,
    val transferFlags: Int,
    val transferBufferLength: Int,
    val startFrame: Int,
    val numberOfPackets: Int,
    val interval: Int,
    val setup: Setup,
    val transferBuffer: ByteArray
) : UrbRequest() {
    /** Parsed USB setup header (8 bytes) from a control transfer. */
    data class Setup(
        val bmRequestType: Int,
        val bRequest: Int,
        val wValue: Int,
        val wIndex: Int,
        val wLength: Int
    ) {
        companion object {
            const val SIZE = 8

            fun parse(bytes: ByteArray): Setup = Setup(
                bmRequestType = bytes[0].toInt() and 0xFF,
                bRequest = bytes[1].toInt() and 0xFF,
                wValue = ((bytes[3].toInt() and 0xFF) shl 8) or (bytes[2].toInt() and 0xFF),
                wIndex = ((bytes[5].toInt() and 0xFF) shl 8) or (bytes[4].toInt() and 0xFF),
                wLength = ((bytes[7].toInt() and 0xFF) shl 8) or (bytes[6].toInt() and 0xFF)
            )
        }
    }

    companion object {
        const val COMMAND = 0x00000001
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as SubmitRequest
        return seqnum == other.seqnum && devid == other.devid && direction == other.direction &&
                ep == other.ep && transferFlags == other.transferFlags &&
                transferBufferLength == other.transferBufferLength &&
                startFrame == other.startFrame && numberOfPackets == other.numberOfPackets &&
                interval == other.interval && setup == other.setup &&
                transferBuffer.contentEquals(other.transferBuffer)
    }

    override fun hashCode(): Int {
        var result = seqnum
        result = 31 * result + devid
        result = 31 * result + direction.hashCode()
        result = 31 * result + ep
        result = 31 * result + transferFlags
        result = 31 * result + transferBufferLength
        result = 31 * result + startFrame
        result = 31 * result + numberOfPackets
        result = 31 * result + interval
        result = 31 * result + setup.hashCode()
        result = 31 * result + transferBuffer.contentHashCode()
        return result
    }

    override fun toString(): String {
        return "SubmitRequest(seqnum=$seqnum, devid=$devid, direction=$direction, ep=$ep, " +
                "transferBufferLength=$transferBufferLength)"
    }
}
