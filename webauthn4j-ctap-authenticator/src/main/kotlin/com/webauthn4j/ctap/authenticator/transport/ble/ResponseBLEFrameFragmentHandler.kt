package com.webauthn4j.ctap.authenticator.transport.ble

fun interface ResponseBLEFrameFragmentHandler {
    fun onResponse(response: ByteArray)
}
