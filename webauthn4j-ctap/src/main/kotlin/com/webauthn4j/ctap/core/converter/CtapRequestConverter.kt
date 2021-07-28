package com.webauthn4j.ctap.core.converter

import com.webauthn4j.converter.util.CborConverter
import com.webauthn4j.converter.util.ObjectConverter
import com.webauthn4j.ctap.core.data.*
import java.nio.ByteBuffer

class CtapRequestConverter(objectConverter: ObjectConverter) {
    private val cborConverter: CborConverter = objectConverter.cborConverter

    /**
     * Converts from a byte array to [CtapRequest].
     *
     * @param source the source byte array to convert
     * @return the converted object
     */
    @Suppress("EXPERIMENTAL_API_USAGE")
    fun convert(source: ByteArray): CtapRequest {
        require(source.isNotEmpty()) { "source must have command type byte." }
        val commandType = source.first().toUByte()
        val commandParameters = source.copyOfRange(1, source.size)
        return when (commandType) {
            0x01.toUByte() -> cborConverter.readValue(
                commandParameters,
                AuthenticatorMakeCredentialRequest::class.java
            )!!
            0x02.toUByte() -> cborConverter.readValue(
                commandParameters,
                AuthenticatorGetAssertionRequest::class.java
            )!!
            0x04.toUByte() -> AuthenticatorGetInfoRequest()
            0x06.toUByte() -> cborConverter.readValue(
                commandParameters,
                AuthenticatorClientPINRequest::class.java
            )!!
            0x07.toUByte() -> AuthenticatorResetRequest()
            0x08.toUByte() -> AuthenticatorGetNextAssertionRequest()
            else -> throw IllegalArgumentException(
                String.format(
                    "unknown command type 0x%x is provided.",
                    commandType
                )
            )
        }
    }

    /**
     * Converts from a [CtapRequest] to byte[].
     *
     * @param source the source object to convert
     * @return concatenation of a command byte and a request data
     */
    @ExperimentalUnsignedTypes
    fun convertToBytes(source: CtapRequest): ByteArray {
        val command = source.command.value
        val requestDataBytes = convertToRequestDataBytes(source)
        return ByteBuffer.allocate(1 + requestDataBytes.size).put(command).put(requestDataBytes)
            .array()
    }

    fun convertToRequestDataBytes(source: CtapRequest): ByteArray {
        return cborConverter.writeValueAsBytes(source)
    }

}