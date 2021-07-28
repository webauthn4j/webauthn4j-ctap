package com.webauthn4j.ctap.authenticator.transport.hid

fun interface HIDPacketHandler {
    fun onResponse(response: ByteArray)
}