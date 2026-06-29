package com.webauthn4j.ctap.authenticator.transport.uhid.usb

import com.webauthn4j.ctap.authenticator.transport.uhid.event.UHIDEvent
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

    open fun writeEvent(event: UHIDEvent) {
        writeBytes(event.toBytes())
    }

    open fun readEvent(): UHIDEvent {
        return UHIDEvent.parse(readBytes())
    }

    open val isOpen: Boolean
        get() = channel?.isOpen == true

    override fun close() {
        channel?.close()
        channel = null
    }

    private fun writeBytes(bytes: ByteArray) {
        val ch = channel ?: throw IllegalStateException("Connection is not open")
        val buf = ByteBuffer.wrap(bytes)
        while (buf.hasRemaining()) {
            ch.write(buf)
        }
    }

    private fun readBytes(): ByteArray {
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
}
