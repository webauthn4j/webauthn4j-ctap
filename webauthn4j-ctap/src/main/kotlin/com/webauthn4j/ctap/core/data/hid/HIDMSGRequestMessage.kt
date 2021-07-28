package com.webauthn4j.ctap.core.data.hid

import com.webauthn4j.ctap.core.util.internal.HexUtil
import com.webauthn4j.util.ArrayUtil
import java.nio.ByteBuffer

class HIDMSGRequestMessage : HIDRequestMessage, HIDMessageBase {

    @Suppress("JoinDeclarationAndAssignment")
    val u2fCommand: Byte

    constructor(channelId: HIDChannelId, u2fCommand: Byte, message: ByteArray) : super(
        channelId,
        HIDCommand.CTAPHID_MSG
    ) {
        this.u2fCommand = u2fCommand
        this.message = ArrayUtil.clone(message)
    }

    val message: ByteArray
        get() = ArrayUtil.clone(field)

    override val data: ByteArray
        get() = ByteBuffer.allocate(1 + message.size).put(u2fCommand).put(message).array()

    override fun toString(): String {
        return "HIDMSGRequestMessage(channelId=${channelId}, command=$command, statusCode=$u2fCommand, message=${
            HexUtil.encodeToString(
                message
            )
        })"
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is HIDMSGRequestMessage) return false
        if (!super.equals(other)) return false

        if (u2fCommand != other.u2fCommand) return false
        if (!message.contentEquals(other.message)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = super.hashCode()
        result = 31 * result + u2fCommand.hashCode()
        result = 31 * result + message.contentHashCode()
        return result
    }


}