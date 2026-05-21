package com.webauthn4j.ctap.authenticator.transport.uhid.event

/**
 * UHID_CLOSE event: userspace closed the device.
 */
data object CloseEvent : UHIDEvent {
    override fun toBytes(): ByteArray = UHIDEvent.createSimpleEvent(UHIDEvent.TYPE_CLOSE)
}
