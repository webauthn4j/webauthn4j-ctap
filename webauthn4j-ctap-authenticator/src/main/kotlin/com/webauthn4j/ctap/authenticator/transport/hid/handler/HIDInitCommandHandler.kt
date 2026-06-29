package com.webauthn4j.ctap.authenticator.transport.hid.handler

import com.webauthn4j.ctap.core.data.hid.HIDCapability
import com.webauthn4j.ctap.core.data.hid.HIDChannelId
import com.webauthn4j.ctap.core.data.hid.HIDINITRequestMessage
import com.webauthn4j.ctap.core.data.hid.HIDINITResponseMessage
import com.webauthn4j.ctap.core.data.hid.HIDResponseMessage

// @see <a href="https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#usb-hid-init">8.1.9.1.3. CTAPHID_INIT</a>
class HIDInitCommandHandler(
    private val channelAllocator: ChannelAllocator
) {

    companion object {
        //spec| The protocol version identifies the protocol version implemented by the device.
        //spec| This version of the CTAPHID protocol is 2.
        private const val HID_PROTOCOL_VERSION_NUMBER: Byte = 2
        private const val MAJOR_DEVICE_VERSION_NUMBER: Byte = 0
        private const val MINOR_DEVICE_VERSION_NUMBER: Byte = 1
        private const val BUILD_DEVICE_VERSION_NUMBER: Byte = 0

        //spec| CAPABILITY_WINK 0x01 If set to 1, authenticator implements CTAPHID_WINK function
        //spec| CAPABILITY_CBOR 0x04 If set to 1, authenticator implements CTAPHID_CBOR function
        //spec| CAPABILITY_NMSG 0x08 If set to 1, authenticator DOES NOT implement CTAPHID_MSG function
        val CAPABILITIES =
            HIDCapability((HIDCapability.WINK.value.toInt() or HIDCapability.CBOR.value.toInt()).toByte())
    }

    suspend fun handle(hidMessage: HIDINITRequestMessage): HIDResponseMessage {
        val channelId = hidMessage.channelId
        val nonce = hidMessage.nonce

        return when (channelId) {
            //spec| If sent on the broadcast CID, it requests the device to allocate a unique 32-bit channel
            //spec| identifier (CID) that can be used by the requesting application during its lifetime.
            HIDChannelId.BROADCAST -> {
                val newChannelId = channelAllocator.allocateChannel()
                HIDINITResponseMessage(
                    channelId, nonce, newChannelId,
                    HID_PROTOCOL_VERSION_NUMBER, MAJOR_DEVICE_VERSION_NUMBER,
                    MINOR_DEVICE_VERSION_NUMBER, BUILD_DEVICE_VERSION_NUMBER,
                    CAPABILITIES
                )
            }
            //spec| If sent on an allocated CID, it synchronizes a channel, discarding the current transaction,
            //spec| buffers and state as quickly as possible. It will then be ready for a new transaction.
            //spec| The device then responds with the CID of the channel it received the INIT on, using that channel.
            else -> {
                channelAllocator.resyncChannel(channelId)
                HIDINITResponseMessage(
                    channelId, nonce, channelId,
                    HID_PROTOCOL_VERSION_NUMBER, MAJOR_DEVICE_VERSION_NUMBER,
                    MINOR_DEVICE_VERSION_NUMBER, BUILD_DEVICE_VERSION_NUMBER,
                    CAPABILITIES
                )
            }
        }
    }

    interface ChannelAllocator {
        fun allocateChannel(): HIDChannelId
        suspend fun resyncChannel(channelId: HIDChannelId)
    }
}
