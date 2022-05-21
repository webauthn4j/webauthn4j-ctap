package com.webauthn4j.ctap.client

interface ClientPINProvider {
    suspend fun provide(): ByteArray
}
