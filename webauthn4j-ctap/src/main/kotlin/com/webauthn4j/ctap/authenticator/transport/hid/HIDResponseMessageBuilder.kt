package com.webauthn4j.ctap.authenticator.transport.hid

import com.webauthn4j.ctap.core.data.StatusCode
import com.webauthn4j.ctap.core.data.hid.*

class HIDResponseMessageBuilder : HIDMessageBuilderBase<HIDResponseMessage>() {
    override fun createMessage(
        channelId: HIDChannelId,
        command: HIDCommand,
        data: ByteArray
    ): HIDResponseMessage {
        return when (command) {
            HIDCommand.CTAPHID_MSG -> {
                val statusCode = StatusCode.create(data.first())
                val message = data.copyOfRange(1, data.size)
                HIDMSGResponseMessage(channelId, statusCode, message)
            }
            HIDCommand.CTAPHID_CBOR -> {
                val statusCode = StatusCode.create(data.first())
                val cbor = data.copyOfRange(1, data.size)
                HIDCBORResponseMessage(channelId, statusCode, cbor)
            }
            HIDCommand.CTAPHID_INIT -> {
                val nonce = data.copyOfRange(0, 8)
                val newChannelId = HIDChannelId(data.copyOfRange(8, 4))
                val hidProtocolVersion = data[12]
                val majorDeviceVersionNumber = data[13]
                val minorDeviceVersionNumber = data[14]
                val buildDeviceVersionNumber = data[15]
                val capabilities = HIDCapability(data[16])
                HIDINITResponseMessage(
                    channelId,
                    nonce,
                    newChannelId,
                    hidProtocolVersion,
                    majorDeviceVersionNumber,
                    minorDeviceVersionNumber,
                    buildDeviceVersionNumber,
                    capabilities
                )
            }
            HIDCommand.CTAPHID_PING -> {
                HIDPINGResponseMessage(channelId, data)
            }
            HIDCommand.CTAPHID_KEEPALIVE -> {
                HIDKEEPALIVEResponseMessage(channelId, HIDStatusCode(data.first()))
            }
            HIDCommand.CTAPHID_WINK -> {
                HIDWINKResponseMessage(channelId)
            }
            HIDCommand.CTAPHID_LOCK -> {
                HIDLOCKResponseMessage(channelId)
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
