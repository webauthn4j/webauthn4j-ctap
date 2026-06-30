package com.webauthn4j.ctap.authenticator.transport.uhid.event

/**
 * UHID_START event: kernel started the device.
 */
data object StartEvent : UHIDEvent {
    override fun toBytes(): ByteArray = UHIDEvent.createSimpleEvent(UHIDEvent.TYPE_START)
}
