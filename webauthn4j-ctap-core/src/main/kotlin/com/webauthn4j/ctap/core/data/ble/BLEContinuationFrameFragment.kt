package com.webauthn4j.ctap.core.data.ble

import com.webauthn4j.util.ArrayUtil
import java.nio.ByteBuffer

class BLEContinuationFrameFragment(seq: Byte, data: ByteArray) : BLEFrameFragment {

    @Suppress("MemberVisibilityCanBePrivate", "CanBePrimaryConstructorProperty")
    val seq = seq

    @Suppress("CanBePrimaryConstructorProperty")
    override val data: ByteArray = ArrayUtil.clone(data)
        get() = ArrayUtil.clone(field)

    override val bytes: ByteArray
        get() {
            val byteBuffer = ByteBuffer.allocate(1 + data.size).put(seq).put(data)
            return byteBuffer.array()
        }

    companion object {

        @JvmStatic
        fun parse(bytes: ByteArray): BLEContinuationFrameFragment {
            require(bytes.isNotEmpty()) { "bytes must not be 0 bytes" }
            val seq = bytes[0]
            val data = bytes.copyOfRange(1, bytes.size)
            return BLEContinuationFrameFragment(seq, data)
        }
    }
}
