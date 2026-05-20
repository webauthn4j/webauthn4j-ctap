package com.webauthn4j.ctap.uhid

import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Path
import java.nio.file.StandardOpenOption

/**
 * Low-level I/O wrapper for /dev/uhid.
 * Reads and writes fixed-size uhid_event structs via FileChannel.
 */
open class UHIDConnection(private val devicePath: String = "/dev/uhid") : AutoCloseable {

    private var channel: FileChannel? = null

    open fun open() {
        channel = FileChannel.open(
            Path.of(devicePath),
            StandardOpenOption.READ,
            StandardOpenOption.WRITE
        )
    }

    open fun writeEvent(eventBytes: ByteArray) {
        val ch = channel ?: throw IllegalStateException("Connection is not open")
        val buf = ByteBuffer.wrap(eventBytes)
        while (buf.hasRemaining()) {
            ch.write(buf)
        }
    }

    open fun readEvent(): ByteArray {
        val ch = channel ?: throw IllegalStateException("Connection is not open")
        val buf = ByteBuffer.allocate(UHIDEvent.EVENT_SIZE)
        while (buf.hasRemaining()) {
            val bytesRead = ch.read(buf)
            if (bytesRead == -1) {
                throw java.io.IOException("End of stream reached on $devicePath")
            }
        }
        return buf.array()
    }

    open val isOpen: Boolean
        get() = channel?.isOpen == true

    override fun close() {
        channel?.close()
        channel = null
    }
}
