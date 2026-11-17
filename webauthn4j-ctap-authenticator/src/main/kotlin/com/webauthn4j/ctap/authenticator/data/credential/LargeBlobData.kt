package com.webauthn4j.ctap.authenticator.data.credential

/** Opaque, DEFLATE-compressed data supplied by the client platform. */
class LargeBlobData @com.fasterxml.jackson.annotation.JsonCreator constructor(@com.fasterxml.jackson.annotation.JsonProperty("compressed") compressed: ByteArray, @com.fasterxml.jackson.annotation.JsonProperty("originalSize") val originalSize: Long) {
    val compressed: ByteArray = compressed.clone()
        get() = field.clone()
    init { require(originalSize >= 0) }
}
