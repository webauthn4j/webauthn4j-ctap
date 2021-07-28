package com.webauthn4j.ctap.authenticator.attestation

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.UncheckedIOException

internal class ResourceLoader {
    fun load(classpath: String): ByteArray {
        try {
            this.javaClass.getResourceAsStream(classpath).use { inputStream ->
                ByteArrayOutputStream().use { byteArrayOutputStream ->
                    val buffer = ByteArray(1024)
                    var length: Int
                    while (inputStream.read(buffer).also { length = it } != -1) {
                        byteArrayOutputStream.write(buffer, 0, length)
                    }
                    return byteArrayOutputStream.toByteArray()
                }
            }
        } catch (e: IOException) {
            throw UncheckedIOException(e)
        }
    }
}