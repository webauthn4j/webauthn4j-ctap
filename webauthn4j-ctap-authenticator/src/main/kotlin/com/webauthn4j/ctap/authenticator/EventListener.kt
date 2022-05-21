package com.webauthn4j.ctap.authenticator

import com.webauthn4j.ctap.authenticator.data.event.Event

/**
 * Listener interface for Authenticator event
 */
fun interface EventListener {
    fun onEvent(event: Event)
}