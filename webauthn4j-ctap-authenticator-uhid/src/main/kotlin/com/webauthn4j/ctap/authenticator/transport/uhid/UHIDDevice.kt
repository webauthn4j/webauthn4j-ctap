package com.webauthn4j.ctap.authenticator.transport.uhid

import com.webauthn4j.ctap.authenticator.CtapAuthenticator
import com.webauthn4j.ctap.authenticator.transport.hid.HIDTransport
import com.webauthn4j.ctap.authenticator.transport.uhid.event.CreateDeviceEvent
import com.webauthn4j.ctap.authenticator.transport.uhid.event.DestroyDeviceEvent
import com.webauthn4j.ctap.authenticator.transport.uhid.event.InputReportEvent
import com.webauthn4j.ctap.authenticator.transport.uhid.event.OutputReportEvent
import com.webauthn4j.ctap.authenticator.transport.uhid.event.CloseEvent
import com.webauthn4j.ctap.authenticator.transport.uhid.event.OpenEvent
import com.webauthn4j.ctap.authenticator.transport.uhid.event.StartEvent
import com.webauthn4j.ctap.authenticator.transport.uhid.event.StopEvent
import com.webauthn4j.ctap.authenticator.transport.uhid.event.UnknownEvent
import com.webauthn4j.ctap.authenticator.transport.uhid.usb.FidoHIDReportDescriptor
import com.webauthn4j.ctap.authenticator.transport.uhid.usb.UHIDConnection
import kotlinx.coroutines.*
import org.slf4j.LoggerFactory
import java.io.IOException
import java.nio.channels.AsynchronousCloseException
import java.nio.channels.ClosedChannelException

/**
 * Virtual USB FIDO2 security key backed by the Linux UHID subsystem.
 *
 * Exposes a [CtapAuthenticator] to the OS as if it were a physical USB HID
 * FIDO2 device.
 */
class UHIDDevice(
    ctapAuthenticator: CtapAuthenticator,
    private val config: UHIDDeviceConfig = UHIDDeviceConfig(),
    private val connection: UHIDConnection = UHIDConnection(config.devicePath)
) : AutoCloseable {

    private val logger = LoggerFactory.getLogger(UHIDDevice::class.java)
    private val hidTransport = HIDTransport(ctapAuthenticator)

    private var readJob: Job? = null
    private var deviceCreated = false

    suspend fun start(scope: CoroutineScope) {
        connection.open()
        createDevice()
        hidTransport.start(scope)
        readJob = scope.launch(Dispatchers.IO) {
            readLoop()
        }
    }

    suspend fun stop() {
        readJob?.cancelAndJoin()
        readJob = null
        hidTransport.close()
        if (deviceCreated) {
            destroyDevice()
        }
        connection.close()
    }

    override fun close() {
        runBlocking { stop() }
    }

    private fun createDevice() {
        connection.writeEvent(CreateDeviceEvent(config, FidoHIDReportDescriptor.DESCRIPTOR))
        deviceCreated = true
        logger.info("Virtual FIDO2 device created: {}", config.deviceName)
    }

    private fun destroyDevice() {
        try {
            connection.writeEvent(DestroyDeviceEvent)
            logger.info("Virtual FIDO2 device destroyed")
        } catch (e: IOException) {
            logger.debug("Failed to send destroy event", e)
        }
        deviceCreated = false
    }

    private suspend fun readLoop() {
        try {
            while (currentCoroutineContext().isActive && connection.isOpen) {
                when (val event = connection.readEvent()) {
                    is OutputReportEvent -> handleOutput(event)
                    is StartEvent -> logger.debug("UHID device started")
                    is StopEvent -> logger.debug("UHID device stopped")
                    is OpenEvent -> logger.debug("UHID device opened by host")
                    is CloseEvent -> logger.debug("UHID device closed by host")
                    is UnknownEvent -> logger.debug("Unknown UHID event type: {}", event.type)
                    is CreateDeviceEvent, is DestroyDeviceEvent, is InputReportEvent -> {}
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

    private fun handleOutput(output: OutputReportEvent) {
        logger.debug("UHID_OUTPUT: size={} (actual HID report: {} bytes), rtype={}",
            output.size, output.data.size, output.rtype)
        hidTransport.onHIDDataReceived(output.data) { responseBytes ->
            synchronized(connection) {
                connection.writeEvent(InputReportEvent(responseBytes))
            }
        }
    }
}
