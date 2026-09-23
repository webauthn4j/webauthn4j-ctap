package com.webauthn4j.ctap.authenticator.transport.hybrid

/** One ordered, reliable binary tunnel. The caller owns WebSocket and TLS details. */
interface HybridDataChannel {
    suspend fun receive(): ByteArray?
    suspend fun send(message: ByteArray)
}
