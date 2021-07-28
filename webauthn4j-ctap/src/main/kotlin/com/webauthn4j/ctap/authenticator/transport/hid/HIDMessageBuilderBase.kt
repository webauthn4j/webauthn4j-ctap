package com.webauthn4j.ctap.authenticator.transport.hid

import com.webauthn4j.ctap.core.data.hid.*
import com.webauthn4j.ctap.core.data.hid.HIDMessage.Companion.MAX_CONT_PACKET_DATA_SIZE
import com.webauthn4j.ctap.core.data.hid.HIDMessage.Companion.MAX_INIT_PACKET_DATA_SIZE
import java.nio.ByteBuffer
import kotlin.math.min

abstract class HIDMessageBuilderBase<T : HIDMessage> {

    private var buffer = ByteBuffer.allocate(0)
    private var counter: Byte = 0
    private var channelId: HIDChannelId? = null
    private var command: HIDCommand? = null

    fun initialize(initializationPacket: HIDInitializationPacket) {
        buffer = ByteBuffer.allocate(initializationPacket.length)
        buffer.put(
            initializationPacket.data,
            0,
            min(
                min(initializationPacket.length, MAX_INIT_PACKET_DATA_SIZE),
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
            throw IllegalStateException("ContinuationPacket with an unexpected sequence number arrived.")//TODO: revisit exception type
        }
        buffer.put(
            continuationPacket.data,
            0,
            min(min(buffer.remaining(), MAX_CONT_PACKET_DATA_SIZE), continuationPacket.data.size)
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