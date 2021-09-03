package com.webauthn4j.ctap.core.data.ble

import com.webauthn4j.util.ArrayUtil
import com.webauthn4j.util.UnsignedNumberUtil
import java.nio.ByteBuffer

class BLEInitializationFrameFragment(val cmd: BLEFrameCommand, val length: UShort, data: ByteArray) :
    BLEFrameFragment {

    override val data: ByteArray
        get() = ArrayUtil.clone(field)

    override val bytes: ByteArray
        get() {
            val byteBuffer = ByteBuffer.allocate(3 + data.size)
            byteBuffer.put(cmd.value)
            byteBuffer.put(UnsignedNumberUtil.toBytes(length.toInt()))
            byteBuffer.put(data)
            return byteBuffer.array()
        }

    companion object {
        @JvmStatic
        fun parse(bytes: ByteArray): BLEInitializationFrameFragment {
            val byteBuffer = ByteBuffer.wrap(bytes)
            val cmd = BLEFrameCommand(byteBuffer.get())
            val length = UnsignedNumberUtil.getUnsignedShort(byteBuffer).toUShort()
            val data = ByteArray(byteBuffer.remaining())
            byteBuffer[data]
            return BLEInitializationFrameFragment(cmd, length, data)
        }
    }

    init {
        this.data = ArrayUtil.clone(data)
    }
}