package com.webauthn4j.ctap.core.data.hid

data class HIDStatusCode(val value: Byte) {
    companion object {
        val PROCESSING = HIDStatusCode(0x01)
        val UPNEEDED = HIDStatusCode(0x02)
    }
}