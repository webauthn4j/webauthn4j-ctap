package com.webauthn4j.ctap.authenticator.transport.hid

import com.webauthn4j.ctap.core.data.hid.HIDChannelId
import com.webauthn4j.ctap.core.data.hid.HIDCommand
import com.webauthn4j.ctap.core.data.hid.HIDContinuationPacket
import com.webauthn4j.ctap.core.data.hid.HIDInitializationPacket
import com.webauthn4j.ctap.core.data.hid.HIDMessage
import com.webauthn4j.ctap.core.data.hid.HIDMessage.Companion.DEFAULT_PACKET_SIZE
import java.nio.ByteBuffer
import kotlin.math.min

abstract class HIDMessageBuilderBase<T : HIDMessage>(
    packetSize: Int = DEFAULT_PACKET_SIZE
) {

    private val maxInitPacketDataSize = HIDMessage.initPacketDataSize(packetSize)
    private val maxContPacketDataSize = HIDMessage.contPacketDataSize(packetSize)

    private var buffer = ByteBuffer.allocate(0)
    private var counter: Byte = 0
    private var channelId: HIDChannelId? = null
    private var command: HIDCommand? = null

    fun initialize(initializationPacket: HIDInitializationPacket) {
        buffer = ByteBuffer.allocate(initializationPacket.length.toInt())
        buffer.put(
            initializationPacket.data,
            0,
            min(
                min(initializationPacket.length.toInt(), maxInitPacketDataSize),
                initializationPacket.data.size
            )
        )
        channelId = initializationPacket.channelId
        command = initializationPacket.command
    }

    fun append(continuationPacket: HIDContinuationPacket) {
        if (!isInitialized) {
            throw IllegalStateException("Builder is not initialized. It seems initialization packet haven't arrived.")
        }
        if (counter != continuationPacket.sec) {
            throw IllegalStateException("ContinuationPacket with an unexpected sequence number arrived.")
        }
        buffer.put(
            continuationPacket.data,
            0,
            min(min(buffer.remaining(), maxContPacketDataSize), continuationPacket.data.size)
        )
        counter++
    }

    val isInitialized: Boolean
        get() = channelId != null

    val isCompleted: Boolean
        get() = !buffer.hasRemaining()

    fun build(): T {
        if (!isCompleted) {
            throw IllegalStateException("HID message not completed")
        }
        return createMessage(channelId!!, command!!, buffer.array())
    }

    fun clear() {
        buffer = ByteBuffer.allocate(0)
        counter = 0
        channelId = null
        command = null
    }

    protected abstract fun createMessage(
        channelId: HIDChannelId,
        command: HIDCommand,
        data: ByteArray
    ): T

}