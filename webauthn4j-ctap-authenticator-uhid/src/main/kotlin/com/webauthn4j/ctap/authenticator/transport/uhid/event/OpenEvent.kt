package com.webauthn4j.ctap.authenticator.transport.uhid.event

/**
 * UHID_OPEN event: userspace opened the device.
 */
data object OpenEvent : UHIDEvent {
    override fun toBytes(): ByteArray = UHIDEvent.createSimpleEvent(UHIDEvent.TYPE_OPEN)
}
