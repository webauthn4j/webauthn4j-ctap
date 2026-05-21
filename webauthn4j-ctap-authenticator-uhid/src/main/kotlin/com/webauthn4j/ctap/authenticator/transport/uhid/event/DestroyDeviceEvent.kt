package com.webauthn4j.ctap.authenticator.transport.uhid.event

/**
 * UHID_DESTROY event: removes the virtual HID device.
 */
data object DestroyDeviceEvent : UHIDEvent {
    override fun toBytes(): ByteArray = UHIDEvent.createSimpleEvent(UHIDEvent.TYPE_DESTROY)
}
