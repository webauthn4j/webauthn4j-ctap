package com.webauthn4j.ctap.core.data.nfc

import com.webauthn4j.util.ArrayUtil
import com.webauthn4j.util.AssertUtil
import java.nio.ByteBuffer
import java.util.*

@Suppress("CanBePrimaryConstructorProperty")
class ResponseAPDU(data: ByteArray?, sw1: Byte, sw2: Byte) {

    companion object {
        private const val SW_LENGTH = 2

        @JvmStatic
        fun createErrorResponseAPDU(): ResponseAPDU {
            val sw1 = 0x6f.toByte()
            val sw2 = 0x00.toByte()
            return ResponseAPDU(sw1, sw2)
        }

        @JvmStatic
        fun parse(value: ByteArray, dataLength: Int): ResponseAPDU {
            AssertUtil.isTrue(
                value.size == dataLength + SW_LENGTH,
                String.format(Locale.US, "value must be %d length.", dataLength + 2)
            )
            val data = value.copyOf(dataLength)
            val sw1 = value[dataLength]
            val sw2 = value[dataLength + 1]
            return ResponseAPDU(data, sw1, sw2)
        }
    }

    private val _data: ByteArray? = ArrayUtil.clone(data)

    val data: ByteArray?
        get() = ArrayUtil.clone(_data)
    val sw1: Byte = sw1
    val sw2: Byte = sw2

    val bytes: ByteArray
        get() = if (_data == null) {
            ByteBuffer.allocate(SW_LENGTH).put(sw1).put(sw2).array()
        } else {
            ByteBuffer.allocate(_data.size + SW_LENGTH).put(_data).put(sw1).put(sw2).array()
        }

    constructor(sw1: Byte, sw2: Byte) : this(null, sw1, sw2)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as ResponseAPDU

        if (_data != null) {
            if (other._data == null) return false
            if (!_data.contentEquals(other._data)) return false
        } else if (other._data != null) return false
        if (sw1 != other.sw1) return false
        if (sw2 != other.sw2) return false

        return true
    }

    override fun hashCode(): Int {
        var result = _data?.contentHashCode() ?: 0
        result = 31 * result + sw1
        result = 31 * result + sw2
        return result
    }
}