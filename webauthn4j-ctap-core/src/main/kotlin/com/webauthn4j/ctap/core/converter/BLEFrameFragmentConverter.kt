package com.webauthn4j.ctap.core.converter

import com.webauthn4j.ctap.core.data.ble.BLEContinuationFrameFragment
import com.webauthn4j.ctap.core.data.ble.BLEFrameFragment
import com.webauthn4j.ctap.core.data.ble.BLEInitializationFrameFragment

@Suppress("EXPERIMENTAL_API_USAGE")
class BLEFrameFragmentConverter {
    fun convert(bytes: ByteArray): BLEFrameFragment {
        require(bytes.isNotEmpty()) { "bytes must not be 0 bytes" }
        val firstByte = bytes.first().toUByte()
        return if ((firstByte and 0b10000000.toUByte()) != 0.toUByte()) { // if first bit is set
            BLEInitializationFrameFragment.parse(bytes)
        } else {
            BLEContinuationFrameFragment.parse(bytes)
        }
    }
}
