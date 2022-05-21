package com.webauthn4j.ctap.core.data.hid

data class HIDCapability(val value: Byte) {
    companion object {
        val WINK = HIDCapability(0x01)
        val CBOR = HIDCapability(0x04)
        val NMSG = HIDCapability(0x08)
    }
}