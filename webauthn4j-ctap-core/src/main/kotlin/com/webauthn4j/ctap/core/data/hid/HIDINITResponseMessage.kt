package com.webauthn4j.ctap.core.data.hid

import com.webauthn4j.ctap.core.util.internal.HexUtil
import com.webauthn4j.util.ArrayUtil
import java.nio.ByteBuffer

class HIDINITResponseMessage : HIDResponseMessage, HIDMessageBase {

    val nonce: ByteArray
    val newChannelId: HIDChannelId
    val hidProtocolVersionNumber: Byte
    val majorDeviceVersionNumber: Byte
    val minorDeviceVersionNumber: Byte
    val buildDeviceVersionNumber: Byte
    val capabilities: HIDCapability

    constructor(
        channelId: HIDChannelId,
        nonce: ByteArray,
        newChannelId: HIDChannelId,
        hidProtocolVersionNumber: Byte,
        majorDeviceVersionNumber: Byte,
        minorDeviceVersionNumber: Byte,
        buildDeviceVersionNumber: Byte,
        capabilities: HIDCapability
    ) : super(channelId, HIDCommand.CTAPHID_INIT) {

        require(nonce.size == 8) { "nonce must be 8 bytes" }

        this.nonce = ArrayUtil.clone(nonce)
        this.newChannelId = newChannelId
        this.hidProtocolVersionNumber = hidProtocolVersionNumber
        this.majorDeviceVersionNumber = majorDeviceVersionNumber
        this.minorDeviceVersionNumber = minorDeviceVersionNumber
        this.buildDeviceVersionNumber = buildDeviceVersionNumber
        this.capabilities = capabilities
    }

    override val data: ByteArray
        get() = ByteBuffer.allocate(17)
            .put(nonce)
            .put(newChannelId.value)
            .put(hidProtocolVersionNumber)
            .put(majorDeviceVersionNumber)
            .put(minorDeviceVersionNumber)
            .put(buildDeviceVersionNumber)
            .put(capabilities.value)
            .array()

    override fun toString(): String {
        return "HIDINITResponseMessage(channelId=${channelId}, command=$command, nonce=${
            HexUtil.encodeToString(
                nonce
            )
        }, newChannelId=${newChannelId} hidProtocolVersionNumber=$hidProtocolVersionNumber, majorDeviceVersionNumber=$majorDeviceVersionNumber, minorDeviceVersionNumber=$minorDeviceVersionNumber, buildDeviceVersionNumber=$buildDeviceVersionNumber, capabilities=$capabilities)"
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is HIDINITResponseMessage) return false
        if (!super.equals(other)) return false

        if (!nonce.contentEquals(other.nonce)) return false
        if (hidProtocolVersionNumber != other.hidProtocolVersionNumber) return false
        if (majorDeviceVersionNumber != other.majorDeviceVersionNumber) return false
        if (minorDeviceVersionNumber != other.minorDeviceVersionNumber) return false
        if (buildDeviceVersionNumber != other.buildDeviceVersionNumber) return false
        if (capabilities != other.capabilities) return false

        return true
    }

    override fun hashCode(): Int {
        var result = super.hashCode()
        result = 31 * result + nonce.contentHashCode()
        result = 31 * result + hidProtocolVersionNumber
        result = 31 * result + majorDeviceVersionNumber
        result = 31 * result + minorDeviceVersionNumber
        result = 31 * result + buildDeviceVersionNumber
        result = 31 * result + capabilities.hashCode()
        return result
    }


}