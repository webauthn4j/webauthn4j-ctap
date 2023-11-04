package com.webauthn4j.ctap.authenticator.transport.hid

import com.webauthn4j.ctap.core.data.CtapStatusCode
import com.webauthn4j.ctap.core.data.hid.HIDCBORResponseMessage
import com.webauthn4j.ctap.core.data.hid.HIDCapability
import com.webauthn4j.ctap.core.data.hid.HIDChannelId
import com.webauthn4j.ctap.core.data.hid.HIDCommand
import com.webauthn4j.ctap.core.data.hid.HIDINITResponseMessage
import com.webauthn4j.ctap.core.data.hid.HIDKEEPALIVEResponseMessage
import com.webauthn4j.ctap.core.data.hid.HIDLOCKResponseMessage
import com.webauthn4j.ctap.core.data.hid.HIDPINGResponseMessage
import com.webauthn4j.ctap.core.data.hid.HIDResponseMessage
import com.webauthn4j.ctap.core.data.hid.HIDStatusCode
import com.webauthn4j.ctap.core.data.hid.HIDWINKResponseMessage

class HIDResponseMessageBuilder : HIDMessageBuilderBase<HIDResponseMessage>() {
    override fun createMessage(
        channelId: HIDChannelId,
        command: HIDCommand,
        data: ByteArray
    ): HIDResponseMessage {
        return when (command) {
            HIDCommand.CTAPHID_MSG -> {
                TODO()
            }
            HIDCommand.CTAPHID_CBOR -> {
                val statusCode = CtapStatusCode.create(data.first())
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
