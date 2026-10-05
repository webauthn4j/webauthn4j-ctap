package com.webauthn4j.ctap.authenticator.transport.usbip

import com.webauthn4j.ctap.authenticator.transport.usbip.endpoint.ControlEndpoint
import com.webauthn4j.ctap.authenticator.transport.usbip.endpoint.InterruptEndpoint
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.writeFully

/** Endpoint state for an imported device. USBIPServer owns discovery and import. */
internal class USBIPSession(
    val readChannel: ByteReadChannel,
    val writeChannel: ByteWriteChannel,
    val controlEndpoint: ControlEndpoint,
    val interruptEndpoint: InterruptEndpoint
) : AutoCloseable {
    suspend fun writeResponse(data: ByteArray) = writeChannel.writeFully(data)

    override fun close() = interruptEndpoint.close()
}
