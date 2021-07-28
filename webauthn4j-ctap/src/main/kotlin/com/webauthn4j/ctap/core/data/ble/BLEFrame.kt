package com.webauthn4j.ctap.core.data.ble

import java.util.*
import kotlin.math.min

class BLEFrame @JvmOverloads constructor(val cmd: BLEFrameCommand, val data: ByteArray? = null) {

    constructor(error: BLEFrameError) : this(BLEFrameCommand.ERROR, byteArrayOf(error.value))

    fun sliceToFragments(maxFragmentSize: Int): List<BLEFrameFragment> {
        var position = 0
        val data = data
        val fragments: MutableList<BLEFrameFragment> = ArrayList()
        var i = 0
        while (position < data!!.size) {
            var bleFrameFragment: BLEFrameFragment
            when {
                i == 0 -> {
                    val maxDataSize = maxFragmentSize - 3
                    val slicedData = sliceData(data, position, maxDataSize)
                    bleFrameFragment = BLEInitializationFrameFragment(cmd, data.size, slicedData)
                    position += slicedData.size
                }
                i <= 0x7f -> {
                    val maxDataSize = maxFragmentSize - 1
                    val slicedData = sliceData(data, position, maxDataSize)
                    bleFrameFragment = BLEContinuationFrameFragment(i.toByte(), slicedData)
                    position += slicedData.size
                }
                else -> throw IllegalStateException("Too large data to slice")
            }
            fragments.add(bleFrameFragment)
            i++
        }
        return fragments
    }

    private fun sliceData(data: ByteArray?, position: Int, maxDataSize: Int): ByteArray {
        val slicedDataSize = min(maxDataSize, data!!.size - position)
        return Arrays.copyOfRange(data, position, position + slicedDataSize)
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as BLEFrame

        if (cmd != other.cmd) return false
        if (data != null) {
            if (other.data == null) return false
            if (!data.contentEquals(other.data)) return false
        } else if (other.data != null) return false

        return true
    }

    override fun hashCode(): Int {
        var result = cmd.hashCode()
        result = 31 * result + (data?.contentHashCode() ?: 0)
        return result
    }
}