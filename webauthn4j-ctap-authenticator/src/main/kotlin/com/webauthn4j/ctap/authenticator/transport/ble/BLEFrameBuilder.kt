package com.webauthn4j.ctap.authenticator.transport.ble

import com.webauthn4j.ctap.core.data.ble.BLEContinuationFrameFragment
import com.webauthn4j.ctap.core.data.ble.BLEFrame
import com.webauthn4j.ctap.core.data.ble.BLEInitializationFrameFragment
import java.nio.ByteBuffer
import java.util.*
import java.util.function.Consumer

internal class BLEFrameBuilder {
    private val continuationFragments: Queue<BLEContinuationFrameFragment> = LinkedList()
    private var initializationFragment: BLEInitializationFrameFragment? = null
    private var remaining = 0L

    fun initialize(initializationFragment: BLEInitializationFrameFragment) {
        this.initializationFragment = initializationFragment
        continuationFragments.clear()
        remaining =
            initializationFragment.length.toLong() - initializationFragment.data.size.toLong()
    }

    fun append(continuationFragment: BLEContinuationFrameFragment) {
        continuationFragments.add(continuationFragment)
        remaining -= continuationFragment.data.size
    }

    val isInitialized: Boolean
        get() = initializationFragment != null

    val isCompleted: Boolean
        get() = remaining == 0L

    fun build(): BLEFrame {
        initializationFragment.let {
            if (it == null) {
                throw IllegalStateException("BLEFrameBuilder is not initialized")
            }
            val byteBuffer = ByteBuffer.allocate(it.length.toInt())
            byteBuffer.put(it.data)
            continuationFragments.forEach(Consumer { continuationFragment: BLEContinuationFrameFragment ->
                byteBuffer.put(
                    continuationFragment.data
                )
            })
            return BLEFrame(it.cmd, byteBuffer.array())
        }
    }
}