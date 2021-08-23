package com.webauthn4j.ctap.core.data.hid

import com.webauthn4j.ctap.core.data.CtapStatusCode
import com.webauthn4j.ctap.core.data.nfc.ResponseAPDU
import com.webauthn4j.ctap.core.util.internal.HexUtil
import com.webauthn4j.util.ArrayUtil
import java.nio.ByteBuffer

class HIDMSGResponseMessage : HIDResponseMessage, HIDMessageBase {

    @Suppress("JoinDeclarationAndAssignment")
    val responseAPDU: ResponseAPDU

    @Suppress("ConvertSecondaryConstructorToPrimary")
    constructor(channelId: HIDChannelId, responseAPDU: ResponseAPDU) : super(
        channelId,
        HIDCommand.CTAPHID_MSG
    ) {
        this.responseAPDU = responseAPDU
    }

    override val data: ByteArray
        get() = responseAPDU.toBytes()

    override fun toString(): String {
        return "HIDMSGResponseMessage(channelId=${channelId}, responseAPDU=${responseAPDU})"
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is HIDMSGResponseMessage) return false
        if (!super.equals(other)) return false

        if (responseAPDU != other.responseAPDU) return false

        return true
    }

    override fun hashCode(): Int {
        var result = super.hashCode()
        result = 31 * result + responseAPDU.hashCode()
        return result
    }


}