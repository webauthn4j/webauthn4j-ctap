package com.webauthn4j.ctap.authenticator.transport.hid

import com.webauthn4j.ctap.core.data.CtapCommand
import com.webauthn4j.ctap.core.data.hid.*
import com.webauthn4j.ctap.core.data.nfc.CommandAPDU

class HIDRequestMessageBuilder : HIDMessageBuilderBase<HIDRequestMessage>() {

    override fun createMessage(
        channelId: HIDChannelId,
        command: HIDCommand,
        data: ByteArray
    ): HIDRequestMessage {
        return when (command) {
            HIDCommand.CTAPHID_MSG -> {
                val commandAPDU = CommandAPDU.parse(data)
                HIDMSGRequestMessage(channelId, commandAPDU)
            }
            HIDCommand.CTAPHID_CBOR -> {
                val ctapCommand = CtapCommand(data.first())
                val cbor = data.copyOfRange(1, data.size)
                HIDCBORRequestMessage(channelId, ctapCommand, cbor)
            }
            HIDCommand.CTAPHID_INIT -> {
                HIDINITRequestMessage(channelId, data)
            }
            HIDCommand.CTAPHID_PING -> {
                HIDPINGRequestMessage(channelId, data)
            }
            HIDCommand.CTAPHID_CANCEL -> {
                HIDCANCELRequestMessage(channelId)
            }
            HIDCommand.CTAPHID_KEEPALIVE -> {
                HIDKEEPALIVEResponseMessage(channelId, HIDStatusCode(data.first()))
            }
            HIDCommand.CTAPHID_WINK -> {
                HIDWINKRequestMessage(channelId)
            }
            HIDCommand.CTAPHID_LOCK -> {
                HIDLOCKRequestMessage(channelId, data.first())
            }
            else -> throw IllegalStateException(
                String.format(
                    "Unexpected HIDCommand received: 0x%02X",
                    command.value
                )
            )
        }
    }
}
