package com.webauthn4j.ctap.authenticator.transport.hybrid

import tools.jackson.dataformat.cbor.CBORMapper
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test

internal class HybridQrPayloadTest {
    @Test
    fun `decimal decoder matches the Rust Hybrid vector`() {
        assertArrayEquals(
            "hello world".toByteArray(),
            HybridQrPayload.decodeDigits("335311851610699281684828783"),
        )
    }

    @Test
    fun `QR parser reads compressed P-256 key and transaction secret`() {
        val key = hex("036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296")
        val secret = ByteArray(16) { it.toByte() }
        val cbor = CBORMapper().writeValueAsBytes(
            mapOf(0 to key, 1 to secret, 2 to 2, 5 to "ga"),
        )

        val payload = HybridQrPayload.fromQrUri("FIDO:/${encodeDigits(cbor)}")

        assertArrayEquals(key, payload.publicKey)
        assertArrayEquals(secret, payload.secret)
        assertEquals(2L, payload.knownTunnelServerDomains)
        assertEquals("ga", payload.operationHint)
    }

    @Test
    fun `QR parser rejects malformed decimal chunks`() {
        assertThrows(IllegalArgumentException::class.java) {
            HybridQrPayload.fromQrUri("FIDO:/99999999999999999")
        }
        assertThrows(IllegalArgumentException::class.java) {
            HybridQrPayload.fromQrUri("FIDO:/123")
        }
    }

    @Test
    fun `tunnel ID agrees with the Rust HKDF vector`() {
        val key = hex("036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296")
        val secret = hex("000102030405060708090a0b0c0d0e0f")
        val cbor = CBORMapper().writeValueAsBytes(mapOf(0 to key, 1 to secret, 2 to 2, 5 to "ga"))
        val qr = HybridQrPayload.fromQrUri("FIDO:/${encodeDigits(cbor)}")
        val transaction = HybridQrTransaction(qr, ByteArray(3), ByteArray(10))

        assertArrayEquals(hex("de1d8150b45f03349b2b00a52e2e893e"), transaction.tunnelId)
        assertEquals(20, transaction.advertisement.size)
    }

    @Test
    fun `advertisement and PSK match independent Hybrid vectors`() {
        val key = hex("036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296")
        val secret = hex("000102030405060708090a0b0c0d0e0f")
        val cbor = CBORMapper().writeValueAsBytes(mapOf(0 to key, 1 to secret, 2 to 2, 5 to "ga"))
        val qr = HybridQrPayload.fromQrUri("FIDO:/${encodeDigits(cbor)}")
        val transaction = HybridQrTransaction(
            qr,
            routingId = hex("aabbcc"),
            nonce = hex("0102030405060708090a"),
        )

        assertArrayEquals(hex("000102030405060708090aaabbcc0000"), transaction.advertisementPlaintext)
        assertArrayEquals(hex("35d007a5bae78986c164f4666e8421909bd69006"), transaction.advertisement)
        assertArrayEquals(hex("fc40f5c2c1b6e516b3088297088ccbe219902d47523d006eefcdbd684d523aca"), transaction.noisePsk)
        assertEquals("cable.ua5v.com", transaction.tunnelDomain)
        assertEquals("/cable/connect/aabbcc/de1d8150b45f03349b2b00a52e2e893e", transaction.tunnelPath)
        assertEquals(
            "cable.x6dnkxkmx2odd.org",
            HybridQrTransaction(qr, encodedTunnelDomain = 0x1234).tunnelDomain,
        )
    }

    private fun hex(value: String): ByteArray = value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    private fun encodeDigits(bytes: ByteArray): String = bytes.toList().chunked(7).joinToString("") { chunk ->
        val value = chunk.foldIndexed(0uL) { index, sum, byte ->
            sum or ((byte.toUByte().toULong()) shl (index * 8))
        }
        val digits = when (chunk.size) {
            7 -> 17
            1 -> 3
            2 -> 5
            3 -> 8
            4 -> 10
            5 -> 13
            else -> 15
        }
        value.toString().padStart(digits, '0')
    }
}
