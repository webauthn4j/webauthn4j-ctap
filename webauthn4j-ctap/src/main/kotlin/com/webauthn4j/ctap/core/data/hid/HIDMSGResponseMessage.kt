package com.webauthn4j.ctap.core.data.hid

import com.webauthn4j.ctap.core.data.StatusCode
import com.webauthn4j.ctap.core.util.internal.HexUtil
import com.webauthn4j.util.ArrayUtil
import java.nio.ByteBuffer

class HIDMSGResponseMessage : HIDResponseMessage, HIDMessageBase {

    @Suppress("JoinDeclarationAndAssignment")
    val statusCode: StatusCode

    @Suppress("ConvertSecondaryConstructorToPrimary")
    constructor(channelId: HIDChannelId, statusCode: StatusCode, message: ByteArray) : super(
        channelId,
        HIDCommand.CTAPHID_MSG
    ) {
        this.statusCode = statusCode
        this.message = ArrayUtil.clone(message)
    }

    val message: ByteArray
        get() = ArrayUtil.clone(field)

    override val data: ByteArray
        get() = ByteBuffer.allocate(1 + message.size).put(statusCode.byte).put(message).array()

    override fun toString(): String {
        return "HIDMSGResponseMessage(channelId=${channelId}, command=$command, statusCode=$statusCode, message=${
            HexUtil.encodeToString(
                message
            )
        })"
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is HIDMSGResponseMessage) return false
        if (!super.equals(other)) return false

        if (statusCode != other.statusCode) return false
        if (!message.contentEquals(other.message)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = super.hashCode()
        result = 31 * result + statusCode.hashCode()
        result = 31 * result + message.contentHashCode()
        return result
    }

}