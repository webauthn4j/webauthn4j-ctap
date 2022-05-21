package com.webauthn4j.ctap.core.data.hid

import com.webauthn4j.ctap.core.data.CtapStatusCode
import com.webauthn4j.ctap.core.util.internal.HexUtil
import com.webauthn4j.util.ArrayUtil
import java.nio.ByteBuffer

class HIDCBORResponseMessage : HIDResponseMessage, HIDMessageBase {

    @Suppress("JoinDeclarationAndAssignment")
    val statusCode: CtapStatusCode

    constructor(channelId: HIDChannelId, statusCode: CtapStatusCode, cbor: ByteArray) : super(
        channelId,
        HIDCommand.CTAPHID_CBOR
    ) {
        this.statusCode = statusCode
        this.cbor = ArrayUtil.clone(cbor)
    }

    val cbor: ByteArray
        get() = ArrayUtil.clone(field)

    override val data: ByteArray
        get() = ByteBuffer.allocate(1 + cbor.size).put(statusCode.byte).put(cbor).array()

    override fun toString(): String {
        return "HIDCBORResponseMessage(channelId=${channelId}, statusCode=$statusCode, cbor=${
            HexUtil.encodeToString(
                cbor
            )
        })"
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is HIDCBORResponseMessage) return false
        if (!super.equals(other)) return false

        if (statusCode != other.statusCode) return false
        if (!cbor.contentEquals(other.cbor)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = super.hashCode()
        result = 31 * result + statusCode.hashCode()
        result = 31 * result + cbor.contentHashCode()
        return result
    }

}