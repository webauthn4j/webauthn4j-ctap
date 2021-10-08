package com.webauthn4j.ctap.authenticator

import com.webauthn4j.ctap.authenticator.data.event.Event

fun interface EventListener {
    fun onEvent(event: Event)
}