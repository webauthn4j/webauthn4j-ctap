package com.webauthn4j.ctap.authenticator.transport.hid.handler

import com.webauthn4j.ctap.core.data.hid.HIDChannelId
import com.webauthn4j.ctap.core.data.hid.HIDLOCKRequestMessage
import com.webauthn4j.ctap.core.data.hid.HIDLOCKResponseMessage

// @see <a href="https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#usb-hid-lock">8.1.9.2.2. CTAPHID_LOCK</a>
//spec| The lock command places an exclusive lock for one channel to communicate with the device. As
//spec| long as the lock is active, any other channel trying to send a message will fail. In order to
//spec| prevent a stalling or crashing application to lock the device indefinitely, a lock time up to
//spec| 10 seconds may be set. An application requiring a longer lock has to send repeating lock
//spec| commands to maintain the lock.
//spec| Lock time in seconds 0..10. A value of 0 immediately releases the lock
class HIDLockCommandHandler(
    private val lockState: LockState
) {

    companion object {
        private const val MAX_LOCK_SECONDS = 10
    }

    fun handle(hidMessage: HIDLOCKRequestMessage, channelId: HIDChannelId): HIDLOCKResponseMessage {
        val seconds = hidMessage.seconds.toInt().coerceIn(0, MAX_LOCK_SECONDS)
        if (seconds == 0) {
            lockState.ownerChannelId = null
        } else {
            lockState.ownerChannelId = channelId
            lockState.expiryTimeMs = System.currentTimeMillis() + seconds * 1000L
        }
        return HIDLOCKResponseMessage(hidMessage.channelId)
    }

    class LockState {
        @Volatile
        var ownerChannelId: HIDChannelId? = null
        @Volatile
        var expiryTimeMs: Long = 0

        fun isActive(): Boolean {
            if (ownerChannelId == null) return false
            if (System.currentTimeMillis() >= expiryTimeMs) {
                ownerChannelId = null
                return false
            }
            return true
        }
    }
}
