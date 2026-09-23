package com.webauthn4j.ctap.authenticator.transport.hybrid

import com.webauthn4j.ctap.authenticator.CtapAuthenticator
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import tools.jackson.dataformat.cbor.CBORMapper

class HybridQrCtapSessionTest {
    @Test
    fun `serves GetInfo over Noise and accepts a shutdown from a Rust initiator`() = runBlocking {
        val qrKey = hex("036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296")
        val secret = ByteArray(16) { it.toByte() }
        val qrCbor = CBORMapper().writeValueAsBytes(mapOf(0 to qrKey, 1 to secret, 2 to 2, 5 to "ga"))
        val qr = HybridQrPayload.fromQrUri("FIDO:/${encodeDigits(qrCbor)}")
        val transaction = HybridQrTransaction(
            qr,
            routingId = hex("aabbcc"),
            nonce = hex("0102030405060708090a"),
        )
        val initial = hex(
            "04550f471003f3df97c3df506ac797f6721fb1a1fb7b8f6f83d224498a65c88e2" +
                "4136093d7012e509a73715cbd0b00a3cc0ff4b5c01b3ffa196ab1fb327036b8e" +
                "610d0ad563e7129e64239ff73e6a09bbe",
        )
        val ctapGetInfo = hex(
            "bc757e14686c7d9fa413029c10d5bf3c1d12a3fb04e6aa727423621c10e6b12f" +
                "4ee13a2fb8c3b49999b19eb4389b0dcc",
        )
        val shutdown = hex(
            "5676b36b78ac76afa29a65d194a54adbd3a30074d1b23a982f58e993f48d46b" +
                "eccc140719175a2b04285c01a46f7cbd6",
        )
        val incoming = ArrayDeque(listOf(initial, ctapGetInfo, shutdown))
        val sent = mutableListOf<ByteArray>()
        val channel = object : HybridDataChannel {
            override suspend fun receive(): ByteArray? = incoming.removeFirstOrNull()
            override suspend fun send(message: ByteArray) { sent.add(message) }
        }
        val processor = HybridCtapProcessor(CtapAuthenticator().createSession())
        val responder = HybridNoiseResponder(qr.publicKey, transaction.noisePsk, ByteArray(32) { 4 })

        HybridQrCtapSession(transaction, processor, responder).serve(channel)

        assertEquals(3, sent.size)
        assertArrayEquals(
            hex(
                "0473103ec30b3ccf57daae08e93534aef144a35940cf6bbba12a0cf7cbd5d65a6" +
                    "4d82c8c99e9d3c45f9245ba9b27982c9aea8ec1db94b19c44795942c0eb22aa3" +
                    "2b0b34315a3482907d60aac66ec2d061c",
            ),
            sent[0],
        )
        assertEquals(16, sent[1].size % 32)
        assertEquals(16, sent[2].size % 32)
    }

    private fun hex(value: String): ByteArray = value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    private fun encodeDigits(bytes: ByteArray): String = bytes.toList().chunked(7).joinToString("") { chunk ->
        val value = chunk.foldIndexed(0uL) { index, sum, byte ->
            sum or (byte.toUByte().toULong() shl (index * 8))
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
