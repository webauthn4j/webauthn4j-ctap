package com.webauthn4j.ctap.core.data.hid

import com.webauthn4j.ctap.core.data.nfc.CommandAPDU

class HIDMSGRequestMessage : HIDRequestMessage, HIDMessageBase {

    @Suppress("JoinDeclarationAndAssignment")
    val commandAPDU: CommandAPDU

    constructor(channelId: HIDChannelId, commandAPDU: CommandAPDU) : super(
        channelId,
        HIDCommand.CTAPHID_MSG
    ) {
        this.commandAPDU = commandAPDU
    }

    override val data: ByteArray
        get() = TODO()

    override fun toString(): String {
        return "HIDMSGRequestMessage(channelId=${channelId}, commandAPDU=$commandAPDU)"
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is HIDMSGRequestMessage) return false
        if (!super.equals(other)) return false

        if (commandAPDU != other.commandAPDU) return false

        return true
    }

    override fun hashCode(): Int {
        var result = super.hashCode()
        result = 31 * result + commandAPDU.hashCode()
        return result
    }


}