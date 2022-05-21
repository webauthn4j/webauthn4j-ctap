package com.webauthn4j.ctap.core.data.hid

import com.webauthn4j.ctap.core.data.CtapCommand
import com.webauthn4j.ctap.core.util.internal.HexUtil
import com.webauthn4j.util.ArrayUtil
import java.nio.ByteBuffer

class HIDCBORRequestMessage : HIDRequestMessage, HIDMessageBase {

    @Suppress("JoinDeclarationAndAssignment")
    val ctapCommand: CtapCommand

    constructor(channelId: HIDChannelId, ctapCommand: CtapCommand, cbor: ByteArray) : super(
        channelId,
        HIDCommand.CTAPHID_CBOR
    ) {
        this.ctapCommand = ctapCommand
        this.cbor = ArrayUtil.clone(cbor)
    }

    val cbor: ByteArray
        get() = ArrayUtil.clone(field)

    override val data: ByteArray
        get() = ByteBuffer.allocate(1 + cbor.size).put(ctapCommand.value).put(cbor).array()

    override fun toString(): String {
        return "HIDCBORRequestMessage(channelId=${channelId}, ctapCommand=$ctapCommand, cbor=${
            HexUtil.encodeToString(
                cbor
            )
        })"
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is HIDCBORRequestMessage) return false
        if (!super.equals(other)) return false

        if (ctapCommand != other.ctapCommand) return false
        if (!cbor.contentEquals(other.cbor)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = super.hashCode()
        result = 31 * result + ctapCommand.hashCode()
        result = 31 * result + cbor.contentHashCode()
        return result
    }

}