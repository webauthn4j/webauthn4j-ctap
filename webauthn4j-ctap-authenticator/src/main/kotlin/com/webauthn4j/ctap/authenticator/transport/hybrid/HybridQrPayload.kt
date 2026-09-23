package com.webauthn4j.ctap.authenticator.transport.hybrid

import tools.jackson.databind.JsonNode
import tools.jackson.dataformat.cbor.CBORMapper
import org.bouncycastle.asn1.sec.SECNamedCurves

/** The phone-side, QR-initiated Hybrid parameters. Each scan creates a new transaction. */
class HybridQrPayload private constructor(
    val publicKey: ByteArray,
    val secret: ByteArray,
    val knownTunnelServerDomains: Long,
    val operationHint: String,
) {
    companion object {
        private val cbor = CBORMapper()
        private val partialChunkLengths = mapOf(3 to 1, 5 to 2, 8 to 3, 10 to 4, 13 to 5, 15 to 6)

        fun fromQrUri(uri: String): HybridQrPayload {
            require(uri.startsWith("FIDO:/")) { "Hybrid QR must use the FIDO scheme" }
            val digits = uri.removePrefix("FIDO:/")
            val bytes = decodeDigits(digits)
            val root = try {
                cbor.readTree(bytes)
            } catch (error: RuntimeException) {
                throw IllegalArgumentException("Hybrid QR contains invalid CBOR", error)
            }
            require(root.isObject) { "Hybrid QR payload must be a CBOR map" }
            val publicKey = root.requiredBinary("0", 33)
            require(publicKey[0] == 2.toByte() || publicKey[0] == 3.toByte()) {
                "Hybrid QR public key must be compressed P-256"
            }
            val curve = SECNamedCurves.getByName("secp256r1").curve
            require(runCatching { curve.decodePoint(publicKey) }.isSuccess) {
                "Hybrid QR public key is not on P-256"
            }
            val secret = root.requiredBinary("1", 16)
            val domains = root.get("2")
            require(domains != null && domains.isIntegralNumber && domains.canConvertToLong() && domains.longValue() >= 0) {
                "Hybrid QR known tunnel domains must be an unsigned integer"
            }
            val hint = root.get("5")
            require(hint != null && hint.isTextual) { "Hybrid QR operation hint is missing" }
            return HybridQrPayload(publicKey, secret, domains.longValue(), hint.textValue())
        }

        /** caBLE encodes seven little-endian bytes as 17 decimal digits. */
        internal fun decodeDigits(digits: String): ByteArray {
            require(digits.isNotEmpty() && digits.all { it in '0'..'9' }) {
                "Hybrid QR contains non-decimal digits"
            }
            val remainder = digits.length % 17
            require(remainder == 0 || remainder in partialChunkLengths) {
                "Hybrid QR has an invalid final digit count"
            }
            val result = ArrayList<Byte>(digits.length * 7 / 17 + 7)
            digits.chunked(17).forEachIndexed { index, chunk ->
                val count = if (index < digits.length / 17) 7 else partialChunkLengths.getValue(remainder)
                val value = chunk.toULongOrNull() ?: throw IllegalArgumentException("Hybrid QR digit chunk overflows")
                require(value < (1uL shl (count * 8))) { "Hybrid QR digit chunk is noncanonical" }
                repeat(count) { offset -> result.add((value shr (offset * 8)).toByte()) }
            }
            return result.toByteArray()
        }

        private fun JsonNode.requiredBinary(name: String, length: Int): ByteArray {
            val field = get(name)
            require(field != null && field.isBinary) { "Hybrid QR field $name must be a byte string" }
            val value = field.binaryValue()
            require(value.size == length) { "Hybrid QR field $name must contain $length bytes" }
            return value
        }
    }
}
