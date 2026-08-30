package com.webauthn4j.ctap.authenticator

import java.time.Instant

// Holds the state for an ongoing credential management enumeration flow.
// Used by both enumerateRPs and enumerateCredentials subcommands.
// The session expires after 30 seconds of inactivity, matching the
// CTAP2.3 specification timer requirements.
class CredentialManagementSession<T>(private val items: List<T>) {

    // Zero-based index into items
    private var index = 0

    // Timer for session expiration (30 seconds)
    private var instant: Instant = Instant.now()

    /**
     * Total number of items in this enumeration session
     */
    val totalItems: Int get() = items.size

    /**
     * Return the current item at the current index
     */
    fun current(): T {
        if (index >= items.size) {
            throw NoSuchElementException()
        }
        return items[index]
    }

    /**
     * Check whether there are more items after the current one
     */
    fun hasNext(): Boolean = index + 1 < items.size

    /**
     * Advance to the next item and return it. Resets the session timer.
     */
    fun next(): T {
        if (!hasNext()) {
            throw NoSuchElementException()
        }
        index++
        resetTimer()
        return items[index]
    }

    /**
     * Check whether this session has expired (30 seconds since last access)
     */
    fun isExpired(): Boolean {
        return Instant.now().epochSecond - instant.epochSecond >= 30
    }

    /**
     * Reset the session timer to the current time
     */
    fun resetTimer() {
        instant = Instant.now()
    }
}
