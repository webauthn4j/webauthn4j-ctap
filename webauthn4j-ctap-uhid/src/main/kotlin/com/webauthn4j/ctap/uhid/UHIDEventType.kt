package com.webauthn4j.ctap.uhid

enum class UHIDEventType(val value: Int) {
    UHID_DESTROY(1),
    UHID_START(2),
    UHID_STOP(3),
    UHID_OPEN(4),
    UHID_CLOSE(5),
    UHID_OUTPUT(6),
    UHID_CREATE2(11),
    UHID_INPUT2(12);

    companion object {
        fun fromValue(value: Int): UHIDEventType? = entries.find { it.value == value }
    }
}
