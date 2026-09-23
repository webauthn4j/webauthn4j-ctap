package com.webauthn4j.ctap.authenticator.transport.hybrid

import java.io.ByteArrayOutputStream

/** Processes one QR-initiated Hybrid session over an application-provided binary channel. */
class HybridQrCtapSession(
    private val transaction: HybridQrTransaction,
    private val processor: HybridCtapProcessor,
    private val responder: HybridNoiseResponder = HybridNoiseResponder(transaction.qr.publicKey, transaction.noisePsk),
) {
    suspend fun serve(channel: HybridDataChannel) {
        val initial = channel.receive() ?: error("Hybrid tunnel closed before Noise handshake")
        val (response, noise) = responder.accept(initial)
        channel.send(response)

        val getInfo = processor.process(byteArrayOf(0x04))
        require(getInfo.isNotEmpty() && getInfo[0] == 0.toByte()) {
            "Hybrid authenticator GetInfo failed"
        }
        channel.send(noise.encrypt(initialMessage(getInfo.copyOfRange(1, getInfo.size))))

        while (true) {
            val frame = channel.receive() ?: return
            val plaintext = noise.decrypt(frame)
            require(plaintext.isNotEmpty()) { "Empty Hybrid message" }
            when (plaintext[0].toInt() and 0xff) {
                0 -> {
                    require(plaintext.size == 1) { "Invalid Hybrid shutdown message" }
                    return
                }
                1 -> {
                    require(plaintext.size > 1) { "Empty Hybrid CTAP command" }
                    val responseBytes = processor.process(plaintext.copyOfRange(1, plaintext.size))
                    channel.send(noise.encrypt(byteArrayOf(1) + responseBytes))
                }
                else -> error("Unsupported Hybrid message type")
            }
        }
    }

    private fun initialMessage(getInfoCbor: ByteArray): ByteArray {
        val output = ByteArrayOutputStream()
        output.write(0xa1) // canonical CBOR map with one key
        output.write(1) // getInfo response, without the CTAP status byte
        when {
            getInfoCbor.size < 24 -> output.write(0x40 + getInfoCbor.size)
            getInfoCbor.size <= 0xff -> {
                output.write(0x58)
                output.write(getInfoCbor.size)
            }
            getInfoCbor.size <= 0xffff -> {
                output.write(0x59)
                output.write(getInfoCbor.size shr 8)
                output.write(getInfoCbor.size)
            }
            else -> error("Hybrid GetInfo response exceeds the supported CBOR size")
        }
        output.write(getInfoCbor)
        return output.toByteArray()
    }
}
