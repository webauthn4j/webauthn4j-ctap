package com.webauthn4j.ctap.core.data.hid

import com.webauthn4j.ctap.core.util.internal.HexUtil
import java.nio.ByteBuffer

class HIDChannelId {

    companion object {
        val BROADCAST =
            HIDChannelId(byteArrayOf(0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte()))
    }

    private val _value: Int

    val value: ByteArray
        get() = ByteBuffer.allocate(4).putInt(_value).array()

    constructor(value: ByteArray) {
        require(value.size == 4) { "value must be 4 bytes" }
        this._value = ByteBuffer.wrap(value).int
    }

    constructor(value: Int) {
        _value = value
    }

    fun next(): HIDChannelId {
        return when (val next = HIDChannelId(_value + 1)) {
            BROADCAST -> next.next()
            else -> next
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is HIDChannelId) return false

        if (!value.contentEquals(other.value)) return false

        return true
    }

    override fun hashCode(): Int {
        return value.contentHashCode()
    }

    override fun toString(): String {
        return HexUtil.encodeToString(value)!!
    }


}