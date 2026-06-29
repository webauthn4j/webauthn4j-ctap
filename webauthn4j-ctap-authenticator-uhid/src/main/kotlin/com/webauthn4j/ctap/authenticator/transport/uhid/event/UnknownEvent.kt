package com.webauthn4j.ctap.authenticator.transport.uhid.event

/**
 * Unknown UHID event type.
 */
data class UnknownEvent(val type: Int) : UHIDEvent {
    override fun toBytes(): ByteArray = UHIDEvent.createSimpleEvent(type)
}
