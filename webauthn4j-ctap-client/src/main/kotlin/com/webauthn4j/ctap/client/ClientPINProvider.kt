package com.webauthn4j.ctap.client

fun interface ClientPINProvider {
    suspend fun provide(): ByteArray
}
