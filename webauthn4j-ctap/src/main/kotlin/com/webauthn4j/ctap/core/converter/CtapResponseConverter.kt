package com.webauthn4j.ctap.core.converter

import com.webauthn4j.converter.util.CborConverter
import com.webauthn4j.converter.util.ObjectConverter
import com.webauthn4j.ctap.core.data.*
import java.nio.ByteBuffer
import java.util.*

class CtapResponseConverter(objectConverter: ObjectConverter) {

    private val cborConverter: CborConverter = objectConverter.cborConverter

    /**
     * Converts from a byte array to [CtapResponse].
     *
     * @param source the source byte array to convert
     * @return the converted object
     */
    fun convert(source: ByteArray?, responseType: Class<*>): CtapResponse? {
        if (source == null) {
            return null
        }
        require(source.isNotEmpty()) { "source must have statusCode byte." }
        val statusCode = CtapStatusCode.create(source.first())
        val responseDataBytes = Arrays.copyOfRange(source, 1, source.size)
        return when (responseType) {
            AuthenticatorMakeCredentialResponse::class.java -> {
                val responseData = cborConverter.readValue(
                    responseDataBytes,
                    AuthenticatorMakeCredentialResponseData::class.java
                )
                AuthenticatorMakeCredentialResponse(statusCode, responseData)
            }
            AuthenticatorGetAssertionResponse::class.java -> {
                val responseData = cborConverter.readValue(
                    responseDataBytes,
                    AuthenticatorGetAssertionResponseData::class.java
                )
                AuthenticatorGetAssertionResponse(statusCode, responseData)
            }
            AuthenticatorGetInfoResponse::class.java -> {
                val responseData = cborConverter.readValue(
                    responseDataBytes,
                    AuthenticatorGetInfoResponseData::class.java
                )
                AuthenticatorGetInfoResponse(statusCode, responseData)
            }
            AuthenticatorClientPINResponse::class.java -> {
                val responseData = cborConverter.readValue(
                    responseDataBytes,
                    AuthenticatorClientPINResponseData::class.java
                )
                AuthenticatorClientPINResponse(statusCode, responseData)
            }
            AuthenticatorResetResponse::class.java -> {
                AuthenticatorResetResponse(statusCode)
            }
            AuthenticatorGetNextAssertionResponse::class.java -> {
                val responseData = cborConverter.readValue(
                    responseDataBytes,
                    AuthenticatorGetNextAssertionResponseData::class.java
                )
                AuthenticatorGetNextAssertionResponse(statusCode, responseData)
            }
            else -> throw IllegalArgumentException("Unsupported response type is provided.")
        }
    }

    /**
     * Converts from a [CtapResponse] to byte[].
     *
     * @param source the source object to convert
     * @return the converted byte array
     */
    fun convertToBytes(source: CtapResponse): ByteArray {
        return if (source.responseData == null) {
            return byteArrayOf(source.statusCode.byte)
        } else {
            val responseData = cborConverter.writeValueAsBytes(source.responseData)
            ByteBuffer.allocate(1 + responseData.size).put(source.statusCode.byte).put(responseData)
                .array()
        }
    }

    fun convertToResponseDataBytes(source: CtapResponse): ByteArray {
        return if (source.responseData == null) {
            byteArrayOf()
        } else {
            cborConverter.writeValueAsBytes(source.responseData)
        }
    }


}