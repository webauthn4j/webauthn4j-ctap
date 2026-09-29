package com.webauthn4j.ctap.authenticator.transport.usbip

import io.ktor.network.sockets.Socket
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancelAndJoin

/** Serializes import against removal. One virtual USB device has one attached host. */
internal class USBIPExport(val device: USBIPDevice) {
    private var available = true
    private var socket: Socket? = null
    private var sessionJob: Job? = null

    @Synchronized
    fun claim(socket: Socket, job: Job): Boolean {
        if (!available || this.socket != null) return false
        this.socket = socket
        sessionJob = job
        return true
    }

    @Synchronized
    fun release(socket: Socket) {
        if (this.socket === socket) {
            this.socket = null
            sessionJob = null
        }
    }

    suspend fun remove() {
        val job = synchronized(this) {
            available = false
            socket?.close()
            sessionJob.also {
                socket = null
                sessionJob = null
            }
        }
        job?.cancelAndJoin()
    }
}
