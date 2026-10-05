package com.webauthn4j.ctap.authenticator.transport.usbip

import com.webauthn4j.ctap.authenticator.CtapAuthenticator
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.net.ServerSocket
import java.net.Socket
import java.nio.ByteBuffer
import java.nio.ByteOrder

class USBIPServerTest {
    private fun device(number: Int) = USBIPDevice(CtapAuthenticator(), USBIPDeviceConfig(busId = "1-$number", devNum = number))

    private fun socket(port: Int) = Socket("127.0.0.1", port).apply { soTimeout = 3000 }

    private fun list(port: Int): List<String> = socket(port).use { socket ->
        socket.getOutputStream().write(byteArrayOf(1, 0x11, 0x80.toByte(), 5, 0, 0, 0, 0))
        val input = socket.getInputStream()
        val header = ByteBuffer.wrap(input.readNBytes(12)).order(ByteOrder.BIG_ENDIAN)
        assertEquals(0, header.getInt(4))
        List(header.getInt(8)) {
            val record = input.readNBytes(312)
            input.readNBytes((record[311].toInt() and 255) * 4)
            String(record, 256, 32, Charsets.US_ASCII).trimEnd('\u0000')
        }
    }

    private fun import(socket: Socket, bus: String): Int {
        val request = ByteBuffer.allocate(40).order(ByteOrder.BIG_ENDIAN)
            .putShort(0x0111).putShort(0x8003.toShort()).putInt(0).put(bus.toByteArray()).array()
        socket.getOutputStream().write(request)
        val status = ByteBuffer.wrap(socket.getInputStream().readNBytes(8)).getInt(4)
        if (status == 0) assertEquals(312, socket.getInputStream().readNBytes(312).size)
        return status
    }

    private fun descriptor(socket: Socket) {
        val request = ByteBuffer.allocate(48).order(ByteOrder.BIG_ENDIAN)
            .putInt(1).putInt(1).putInt(0x10001).putInt(1).putInt(0)
            .putInt(0).putInt(9).putInt(0).putInt(-1).putInt(0)
            .put(byteArrayOf(0x80.toByte(), 6, 0, 2, 0, 0, 9, 0)).array()
        socket.getOutputStream().write(request)
        val response = socket.getInputStream().readNBytes(48)
        assertEquals(0, ByteBuffer.wrap(response).getInt(20))
        assertEquals(9, ByteBuffer.wrap(response).getInt(24))
        assertEquals(9, socket.getInputStream().readNBytes(9).size)
    }

    private fun withServer(test: suspend (USBIPServer, Int) -> Unit) = runBlocking {
        val port = ServerSocket(0).use { it.localPort }
        val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
        val server = USBIPServer("127.0.0.1", port)
        server.start(scope)
        try {
            withContext(Dispatchers.IO) { test(server, port) }
        } finally {
            server.stop()
            scope.cancel()
        }
    }

    @Test
    fun `one listener enumerates independent devices and permits an empty list`() = withServer { server, port ->
        assertEquals(emptyList<String>(), list(port))
        server.addDevice(device(1))
        server.addDevice(device(2))
        assertEquals(listOf("1-1", "1-2"), list(port))
        socket(port).use { first ->
            socket(port).use { second ->
                assertEquals(0, import(first, "1-1"))
                assertEquals(0, import(second, "1-2"))
                descriptor(first)
                descriptor(second)
            }
        }
    }

    @Test
    fun `removal closes only its own connection and readdition accepts a fresh import`() = withServer { server, port ->
        val first = device(1)
        server.addDevice(first)
        server.addDevice(device(2))
        socket(port).use { a ->
            socket(port).use { b ->
                assertEquals(0, import(a, "1-1"))
                assertEquals(0, import(b, "1-2"))
                assertTrue(server.removeDevice("1-1"))
                assertEquals(-1, a.getInputStream().read())
                assertEquals(listOf("1-2"), list(port))
                descriptor(b)
                server.addDevice(first)
                assertEquals(listOf("1-2", "1-1"), list(port))
                socket(port).use { reattached ->
                    assertEquals(0, import(reattached, "1-1"))
                    descriptor(reattached)
                }
            }
        }
        assertFalse(server.removeDevice("1-99"))
    }

    @Test
    fun `unknown and already imported devices fail without affecting another device`() = withServer { server, port ->
        server.addDevice(device(1))
        socket(port).use { unknown -> assertNotEquals(0, import(unknown, "1-99")) }
        socket(port).use { first ->
            assertEquals(0, import(first, "1-1"))
            socket(port).use { busy -> assertNotEquals(0, import(busy, "1-1")) }
            descriptor(first)
        }
    }

    @Test
    fun `duplicate USB identities are rejected`() = withServer { server, _ ->
        server.addDevice(device(1))
        assertThrows(IllegalArgumentException::class.java) { server.addDevice(device(1)) }
        assertThrows(IllegalArgumentException::class.java) {
            server.addDevice(USBIPDevice(CtapAuthenticator(), USBIPDeviceConfig(busId = "1-2", devNum = 1)))
        }
        assertEquals(1, server.devices().size)
    }
}
