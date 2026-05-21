package com.webauthn4j.ctap.usbip

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import org.slf4j.LoggerFactory
import java.io.IOException
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.ServerSocketChannel
import java.nio.channels.SocketChannel
import java.nio.channels.SelectionKey
import java.nio.channels.Selector

/**
 * USB-IP protocol server handling TCP connections and URB processing.
 * Implements the USB-IP protocol state machine.
 */
class USBIPServer(
    private val config: USBIPDeviceConfig,
    private val urbHandler: suspend (USBIPProtocol.URBSubmit) -> USBIPProtocol.URBResult
) {
    private val logger = LoggerFactory.getLogger(USBIPServer::class.java)

    @Volatile
    private var serverSocket: ServerSocketChannel? = null
    private val clients = mutableListOf<ClientHandler>()

    /**
     * Starts the USB-IP server and begins accepting connections.
     */
    suspend fun start(scope: CoroutineScope) {
        try {
            serverSocket = ServerSocketChannel.open().apply {
                configureBlocking(false)
                bind(InetSocketAddress(config.host, config.port))
            }

            logger.info("USB-IP server listening on {}:{}", config.host, config.port)

            val selector = Selector.open()
            serverSocket?.register(selector, SelectionKey.OP_ACCEPT)

            while (scope.isActive) {
                selector.select(100)

                val keys = selector.selectedKeys()
                for (key in keys) {
                    try {
                        when {
                            key.isAcceptable -> acceptClient(selector, scope)
                            key.isReadable -> {
                                val client = key.attachment() as? ClientHandler
                                client?.handleRead()
                            }
                        }
                    } catch (e: IOException) {
                        logger.debug("I/O error in selector loop", e)
                        val client = key.attachment() as? ClientHandler
                        client?.close()
                    }
                }
                keys.clear()
            }
        } catch (e: IOException) {
            logger.error("Failed to start USB-IP server", e)
            throw e
        } finally {
            stop()
        }
    }

    /**
     * Accepts a new client connection.
     */
    private fun acceptClient(selector: Selector, scope: CoroutineScope) {
        val clientSocket = serverSocket?.accept() ?: return
        clientSocket.configureBlocking(false)

        logger.info("Client connected from {}", clientSocket.remoteAddress)

        val client = ClientHandler(clientSocket, config, urbHandler, scope)
        synchronized(clients) {
            clients.add(client)
        }

        clientSocket.register(selector, SelectionKey.OP_READ, client)
    }

    /**
     * Stops the server and closes all connections.
     */
    fun stop() {
        logger.info("Stopping USB-IP server")
        synchronized(clients) {
            clients.forEach { it.close() }
            clients.clear()
        }
        serverSocket?.close()
        serverSocket = null
    }

    /**
     * Handles a single client connection through the USB-IP protocol state machine.
     */
    private class ClientHandler(
        private val socket: SocketChannel,
        private val config: USBIPDeviceConfig,
        private val urbHandler: suspend (USBIPProtocol.URBSubmit) -> USBIPProtocol.URBResult,
        private val scope: CoroutineScope
    ) {
        private val logger = LoggerFactory.getLogger(ClientHandler::class.java)
        private var attached = false

        /**
         * Handles incoming data from the client.
         */
        fun handleRead() {
            try {
                val headerBuffer = ByteBuffer.allocate(8)
                val bytesRead = socket.read(headerBuffer)

                if (bytesRead == -1) {
                    logger.info("Client disconnected")
                    close()
                    return
                }

                if (bytesRead < 8) {
                    logger.warn("Incomplete header received: {} bytes", bytesRead)
                    return
                }

                headerBuffer.flip()

                // Parse command header
                val version = headerBuffer.short.toInt() and 0xFFFF
                val opCode = headerBuffer.short.toInt() and 0xFFFF

                logger.debug("Received command: version=0x{}, opCode=0x{}",
                    Integer.toHexString(version),
                    Integer.toHexString(opCode))

                when (opCode) {
                    USBIPProtocol.OP_REQ_DEVLIST -> handleDevlist()
                    USBIPProtocol.OP_REQ_IMPORT -> handleImport(headerBuffer)
                    USBIPProtocol.USBIP_CMD_SUBMIT -> handleCmdSubmit(headerBuffer)
                    USBIPProtocol.USBIP_CMD_UNLINK -> handleCmdUnlink(headerBuffer)
                    else -> logger.warn("Unknown opcode: 0x{}", Integer.toHexString(opCode))
                }
            } catch (e: IOException) {
                logger.debug("Client I/O error", e)
                close()
            }
        }

        /**
         * Handles OP_REQ_DEVLIST request.
         */
        private fun handleDevlist() {
            logger.debug("Handling OP_REQ_DEVLIST")
            val device = createDeviceInfo()
            val response = USBIPProtocol.serializeOpRepDevlist(listOf(device))
            socket.write(ByteBuffer.wrap(response))
            logger.debug("Sent device list with {} device(s)", 1)
        }

        /**
         * Handles OP_REQ_IMPORT request.
         */
        private fun handleImport(headerBuffer: ByteBuffer) {
            // Read busid (32 bytes)
            val busIdBuffer = ByteBuffer.allocate(32)
            socket.read(busIdBuffer)
            busIdBuffer.flip()

            val busId = USBIPProtocol.parseOpReqImport(busIdBuffer)
            logger.debug("Handling OP_REQ_IMPORT: busid={}", busId)

            if (busId == config.busId) {
                attached = true
                val device = createDeviceInfo()
                val response = USBIPProtocol.serializeOpRepImport(device)
                socket.write(ByteBuffer.wrap(response))
                logger.info("Device attached to client")
            } else {
                logger.warn("Import request for unknown busid: {}", busId)
            }
        }

        /**
         * Handles USBIP_CMD_SUBMIT command.
         */
        private fun handleCmdSubmit(headerBuffer: ByteBuffer) {
            // Read rest of header (40 more bytes)
            val cmdBuffer = ByteBuffer.allocate(40)
            socket.read(cmdBuffer)
            cmdBuffer.flip()

            // Combine header + command data
            val fullBuffer = ByteBuffer.allocate(48)
            fullBuffer.put(headerBuffer)
            fullBuffer.put(cmdBuffer)
            fullBuffer.flip()
            fullBuffer.position(4)  // Skip command code

            var urb = USBIPProtocol.parseCmdSubmit(fullBuffer)

            // Read URB data if present (OUT transfer)
            if (urb.direction == USBIPProtocol.USBIP_DIR_OUT && urb.transferBufferLength > 0) {
                val dataBuffer = ByteArray(urb.transferBufferLength)
                val dataBuf = ByteBuffer.wrap(dataBuffer)
                socket.read(dataBuf)

                // Update URB with actual data
                urb = urb.copy(data = dataBuffer)
            }

            logger.trace("CMD_SUBMIT: ep=0x{}, dir={}, len={}",
                Integer.toHexString(urb.ep),
                urb.direction,
                urb.transferBufferLength)

            // Process URB asynchronously
            scope.launch(Dispatchers.IO) {
                try {
                    val result = urbHandler(urb)
                    val response = USBIPProtocol.serializeRetSubmit(result)
                    synchronized(socket) {
                        socket.write(ByteBuffer.wrap(response))
                    }
                } catch (e: Exception) {
                    logger.error("Error processing URB", e)
                }
            }
        }

        /**
         * Handles USBIP_CMD_UNLINK command (URB cancellation).
         */
        private fun handleCmdUnlink(headerBuffer: ByteBuffer) {
            logger.debug("Handling CMD_UNLINK (not implemented)")
            // For now, just acknowledge - real implementation would cancel pending URB
        }

        /**
         * Creates device information for this virtual FIDO device.
         */
        private fun createDeviceInfo(): USBIPProtocol.DeviceInfo {
            return USBIPProtocol.DeviceInfo(
                path = "/sys/devices/virtual/usbip/${config.busId}",
                busid = config.busId,
                busnum = config.busNum,
                devnum = config.devNum,
                speed = 3,  // USB 2.0 Full Speed
                idVendor = config.vendorId,
                idProduct = config.productId,
                bcdDevice = config.version,
                bDeviceClass = 0,    // Defined in interface
                bDeviceSubClass = 0,
                bDeviceProtocol = 0,
                bConfigurationValue = 1,
                bNumConfigurations = 1,
                bNumInterfaces = 1
            )
        }

        /**
         * Closes the client connection.
         */
        fun close() {
            try {
                socket.close()
                logger.info("Client connection closed")
            } catch (e: IOException) {
                logger.debug("Error closing client socket", e)
            }
        }
    }
}
