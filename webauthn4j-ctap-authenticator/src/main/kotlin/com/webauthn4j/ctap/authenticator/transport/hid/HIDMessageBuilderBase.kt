package com.webauthn4j.ctap.authenticator.transport.hid

import com.webauthn4j.ctap.core.data.hid.HIDChannelId
import com.webauthn4j.ctap.core.data.hid.HIDCommand
import com.webauthn4j.ctap.core.data.hid.HIDContinuationPacket
import com.webauthn4j.ctap.core.data.hid.HIDErrorCode
import com.webauthn4j.ctap.core.data.hid.HIDInitializationPacket
import com.webauthn4j.ctap.core.data.hid.HIDMessage
import com.webauthn4j.ctap.core.data.hid.HIDMessage.Companion.DEFAULT_PACKET_SIZE
import java.nio.ByteBuffer
import kotlin.math.min

abstract class HIDMessageBuilderBase<T : HIDMessage>(
    private val packetSize: Int = DEFAULT_PACKET_SIZE
) {

    companion object {
        private const val MESSAGE_TIMEOUT_MS = 500L
    }

    private var buffer = ByteBuffer.allocate(0)
    private var counter: Byte = 0
    private var channelId: HIDChannelId? = null
    private var command: HIDCommand? = null
    private var messageStartTimeMs: Long = 0

    fun initialize(initializationPacket: HIDInitializationPacket) {
        buffer = ByteBuffer.allocate(initializationPacket.length.toInt())
        val initDataSize = HIDMessage.initPacketDataSize(packetSize)
        buffer.put(
            initializationPacket.data,
            0,
            min(
                min(initializationPacket.length.toInt(), initDataSize),
                initializationPacket.data.size
            )
        )
        channelId = initializationPacket.channelId
        command = initializationPacket.command
        messageStartTimeMs = System.currentTimeMillis()
    }

    fun append(continuationPacket: HIDContinuationPacket) {
        if (!isInitialized) {
            throw HIDProtocolException(HIDErrorCode.INVALID_SEQ, "Builder is not initialized. It seems initialization packet haven't arrived.")
        }
        if (counter != continuationPacket.sec) {
            throw HIDProtocolException(HIDErrorCode.INVALID_SEQ, "ContinuationPacket with an unexpected sequence number arrived.")
        }
        val contDataSize = HIDMessage.contPacketDataSize(packetSize)
        buffer.put(
            continuationPacket.data,
            0,
            min(min(buffer.remaining(), contDataSize), continuationPacket.data.size)
        )
        counter++
    }

    val isInitialized: Boolean
        get() = channelId != null

    val isCompleted: Boolean
        get() = !buffer.hasRemaining()

    val isTimedOut: Boolean
        get() = isInitialized && !isCompleted &&
                (System.currentTimeMillis() - messageStartTimeMs) > MESSAGE_TIMEOUT_MS

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
        messageStartTimeMs = 0
    }

    protected abstract fun createMessage(
        channelId: HIDChannelId,
        command: HIDCommand,
        data: ByteArray
    ): T

}