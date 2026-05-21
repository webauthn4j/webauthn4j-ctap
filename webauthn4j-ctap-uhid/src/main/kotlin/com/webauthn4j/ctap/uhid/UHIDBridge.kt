package com.webauthn4j.ctap.uhid

import com.webauthn4j.ctap.authenticator.CtapAuthenticator
import com.webauthn4j.ctap.authenticator.transport.hid.HIDTransport
import kotlinx.coroutines.*
import org.slf4j.LoggerFactory
import java.io.IOException
import java.nio.channels.AsynchronousCloseException
import java.nio.channels.ClosedChannelException

/**
 * Bridges a [CtapAuthenticator] to the Linux UHID subsystem, making it appear
 * as a physical USB FIDO2 security key to the OS.
 *
 * Usage:
 * ```
 * val bridge = UHIDBridge(ctapAuthenticator)
 * bridge.start(coroutineScope)
 * // ... the device is now visible to browsers and FIDO2 clients
 * bridge.stop()
 * ```
 */
class UHIDBridge(
    ctapAuthenticator: CtapAuthenticator,
    private val config: UHIDDeviceConfig = UHIDDeviceConfig(),
    private val connection: UHIDConnection = UHIDConnection(config.devicePath)
) : AutoCloseable {

    private val logger = LoggerFactory.getLogger(UHIDBridge::class.java)
    private val hidTransport = HIDTransport(ctapAuthenticator)

    private var readJob: Job? = null
    private var deviceCreated = false

    /**
     * Opens the UHID connection, creates the virtual HID device, and starts
     * the event read loop in the given coroutine scope.
     */
    suspend fun start(scope: CoroutineScope) {
        connection.open()
        createDevice()
        readJob = scope.launch(Dispatchers.IO) {
            readLoop()
        }
    }

    /**
     * Stops the event read loop, destroys the virtual device, and closes the connection.
     */
    suspend fun stop() {
        readJob?.cancelAndJoin()
        readJob = null
        if (deviceCreated) {
            destroyDevice()
        }
        connection.close()
    }

    override fun close() {
        runBlocking { stop() }
    }

    private fun createDevice() {
        val event = UHIDEvent.createCreate2(config, FidoHIDReportDescriptor.DESCRIPTOR)
        logger.debug("Creating UHID device with report descriptor size: {}", FidoHIDReportDescriptor.DESCRIPTOR.size)
        logger.debug("Report descriptor hex: {}", FidoHIDReportDescriptor.DESCRIPTOR.joinToString(" ") { "%02X".format(it.toInt() and 0xFF) })
        logger.debug("Device config: name={}, vid=0x{}, pid=0x{}",
            config.deviceName,
            Integer.toHexString(config.vendorId),
            Integer.toHexString(config.productId))
        connection.writeEvent(event)
        deviceCreated = true
        logger.info("Virtual FIDO2 device created: {}", config.deviceName)
    }

    private fun destroyDevice() {
        try {
            connection.writeEvent(UHIDEvent.createDestroy())
            logger.info("Virtual FIDO2 device destroyed")
        } catch (e: IOException) {
            logger.debug("Failed to send destroy event", e)
        }
        deviceCreated = false
    }

    private suspend fun readLoop() {
        try {
            while (currentCoroutineContext().isActive && connection.isOpen) {
                val eventBytes = connection.readEvent()
                val eventType = UHIDEvent.parseType(eventBytes) ?: continue

                when (eventType) {
                    UHIDEventType.UHID_START -> logger.debug("UHID device started")
                    UHIDEventType.UHID_STOP -> logger.debug("UHID device stopped")
                    UHIDEventType.UHID_OPEN -> logger.debug("UHID device opened by host")
                    UHIDEventType.UHID_CLOSE -> logger.debug("UHID device closed by host")
                    UHIDEventType.UHID_OUTPUT -> handleOutput(eventBytes)
                    else -> logger.debug("Unhandled UHID event: {}", eventType)
                }
            }
        } catch (_: ClosedChannelException) {
            logger.debug("UHID connection closed")
        } catch (_: AsynchronousCloseException) {
            logger.debug("UHID connection closed asynchronously")
        } catch (e: IOException) {
            logger.error("I/O error in UHID read loop", e)
        }
    }

    private suspend fun handleOutput(eventBytes: ByteArray) {
        val output = UHIDEvent.parseOutput(eventBytes)
        val reportBytes = output.data
        logger.debug("UHID_OUTPUT: size={} (actual HID report: {} bytes), rtype={}",
            output.size, reportBytes.size, output.rtype)
        hidTransport.onHIDDataReceived(reportBytes) { responseBytes ->
            sendInput(responseBytes)
        }
    }

    private fun sendInput(packetBytes: ByteArray) {
        val event = UHIDEvent.createInput2(packetBytes)
        connection.writeEvent(event)
    }
}
