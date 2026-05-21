package com.webauthn4j.ctap.authenticator.transport.uhid.event

/**
 * UHID_STOP event: kernel stopped the device.
 */
data object StopEvent : UHIDEvent {
    override fun toBytes(): ByteArray = UHIDEvent.createSimpleEvent(UHIDEvent.TYPE_STOP)
}
