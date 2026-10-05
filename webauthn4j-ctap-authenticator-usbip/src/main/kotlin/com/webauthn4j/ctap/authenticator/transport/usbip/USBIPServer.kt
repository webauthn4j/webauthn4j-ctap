package com.webauthn4j.ctap.authenticator.transport.usbip

import com.webauthn4j.ctap.authenticator.transport.hid.HIDTransport
import com.webauthn4j.ctap.authenticator.transport.usbip.data.handshake.DeviceListRequest
import com.webauthn4j.ctap.authenticator.transport.usbip.data.handshake.DeviceListResponse
import com.webauthn4j.ctap.authenticator.transport.usbip.data.handshake.HandshakeRequest
import com.webauthn4j.ctap.authenticator.transport.usbip.data.handshake.ImportRequest
import com.webauthn4j.ctap.authenticator.transport.usbip.data.handshake.ImportResponse
import com.webauthn4j.ctap.authenticator.transport.usbip.endpoint.ControlEndpoint
import com.webauthn4j.ctap.authenticator.transport.usbip.endpoint.InterruptEndpoint
import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.ServerSocket
import io.ktor.network.sockets.Socket
import io.ktor.network.sockets.aSocket
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import io.ktor.utils.io.writeFully
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.isActive
import kotlinx.coroutines.job
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.supervisorScope
import org.slf4j.LoggerFactory
import java.io.IOException

/**
 * Exposes multiple virtual FIDO2 USB devices through a single USB/IP listener.
 * [addDevice] makes a device discoverable; [removeDevice] also disconnects its host
 * and cancels ongoing CTAP requests. Removing and adding the same device preserves
 * the authenticator's credential store while resetting its HID transport session.
 */
class USBIPServer(private val host: String = "0.0.0.0", private val port: Int = 3240) : AutoCloseable {
    init { require(port in 0..65535) { "Port must be 0-65535" } }

    private val logger = LoggerFactory.getLogger(USBIPServer::class.java)
    private val exports = LinkedHashMap<String, USBIPExport>()
    private var listener: ServerSocket? = null
    private var selector: SelectorManager? = null
    private var serverJob: Job? = null

    fun addDevice(device: USBIPDevice) {
        synchronized(exports) {
            require(!exports.containsKey(device.config.busId)) { "Bus ID is already exported: ${device.config.busId}" }
            require(exports.values.none {
                it.device.config.busNum == device.config.busNum && it.device.config.devNum == device.config.devNum
            }) { "USB bus/device number is already exported" }
            exports[device.config.busId] = USBIPExport(device)
        }
    }

    fun devices(): List<USBIPDevice> = synchronized(exports) { exports.values.map { it.device } }

    suspend fun removeDevice(busId: String): Boolean {
        val export = synchronized(exports) { exports.remove(busId) } ?: return false
        export.remove()
        return true
    }

    /** Binds before returning, so the listener is ready when this call completes. */
    suspend fun start(scope: CoroutineScope) {
        check(listener == null) { "Server is already running" }
        val sm = SelectorManager(Dispatchers.IO)
        val socket = try {
            aSocket(sm).tcp().bind(host, port)
        } catch (error: Exception) {
            sm.close()
            throw error
        }
        selector = sm
        listener = socket
        serverJob = scope.launch(Dispatchers.IO) {
            supervisorScope {
                while (isActive) {
                    val client = socket.accept()
                    launch {
                        try {
                            client.use { serve(it) }
                        } catch (error: CancellationException) {
                            throw error
                        } catch (error: IOException) {
                            logger.debug("USB/IP connection closed: {}", error.message)
                        } catch (error: Exception) {
                            logger.warn("USB/IP session failed", error)
                        }
                    }
                }
            }
        }
    }

    suspend fun stop() {
        serverJob?.cancelAndJoin()
        serverJob = null
        listener?.close()
        listener = null
        selector?.close()
        selector = null
        val removed = synchronized(exports) { exports.values.toList().also { exports.clear() } }
        for (export in removed) export.remove()
    }

    override fun close() = runBlocking { stop() }

    private suspend fun serve(socket: Socket) {
        val input = socket.openReadChannel()
        val output = socket.openWriteChannel(autoFlush = true)
        while (currentCoroutineContext().isActive) {
            when (val request = HandshakeRequest.parse(input)) {
                is DeviceListRequest -> output.writeFully(DeviceListResponse(devices().map { it.deviceInfo }).toBytes())
                is ImportRequest -> {
                    val export = synchronized(exports) { exports[request.busId] }
                    if (export == null || !export.claim(socket, currentCoroutineContext().job)) {
                        // OP_REP_IMPORT failure has no device record.
                        output.writeFully(byteArrayOf(0x01, 0x11, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01))
                        return
                    }
                    try {
                        output.writeFully(ImportResponse(device = export.device.deviceInfo).toBytes())
                        coroutineScope {
                            val hid = HIDTransport(export.device.ctapAuthenticator)
                            hid.start(this)
                            try {
                                USBIPSession(input, output, ControlEndpoint(export.device.config), InterruptEndpoint(hid)).use {
                                    hid.onDeviceAttached()
                                    URBProcessor(it).process()
                                }
                            } finally {
                                hid.close()
                            }
                        }
                    } finally {
                        export.release(socket)
                    }
                    return
                }
            }
        }
    }
}
