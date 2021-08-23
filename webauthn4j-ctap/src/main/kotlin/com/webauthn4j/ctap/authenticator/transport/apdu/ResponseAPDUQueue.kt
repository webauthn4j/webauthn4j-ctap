package com.webauthn4j.ctap.authenticator.transport.apdu

import com.webauthn4j.ctap.core.data.nfc.CommandAPDU
import com.webauthn4j.ctap.core.data.nfc.ResponseAPDU
import java.nio.ByteBuffer
import kotlin.math.min

/**
 * Queue to build [ResponseAPDU]
 */
internal class ResponseAPDUQueue {
    private var byteBuffer: ByteBuffer = ByteBuffer.allocate(0)

    /**
     * initialize queue with data
     */
    fun initialize(data: ByteArray) {
        byteBuffer = ByteBuffer.wrap(data)
    }

    /**
     * poll data from queue and build [ResponseAPDU]
     * @param command [CommandAPDU] to be used for fixing response data size
     */
    fun poll(command: CommandAPDU): ResponseAPDU {
        val data: ByteArray
        val sw1: Byte
        val sw2: Byte
        if (byteBuffer.hasRemaining()) {
            val maxDataSize = command.maxResponseDataSize
            val dataSize = min(maxDataSize, byteBuffer.remaining())
            data = ByteArray(dataSize)
            byteBuffer.get(data)
            if (byteBuffer.hasRemaining()) {
                sw1 = 0x61.toByte()
                sw2 = 0x00.toByte()
            } else {
                sw1 = 0x90.toByte()
                sw2 = 0x00.toByte()
            }
        } else {
            data = ByteArray(0)
            sw1 = 0x90.toByte()
            sw2 = 0x00.toByte()
        }
        return ResponseAPDU(data, sw1, sw2)
    }

    /**
     * clear queue
     */
    fun clear() {
        byteBuffer.clear()
    }
}