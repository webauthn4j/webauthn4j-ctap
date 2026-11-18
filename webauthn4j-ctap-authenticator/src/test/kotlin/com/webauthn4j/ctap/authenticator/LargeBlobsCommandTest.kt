package com.webauthn4j.ctap.authenticator

import com.webauthn4j.ctap.authenticator.extension.LargeBlobKeyExtensionProcessor
import com.webauthn4j.ctap.core.data.*
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest

class LargeBlobsCommandTest {
    @Test
    fun fragmentsRequireWritePermissionAndBecomeVisibleOnlyAfterChecksumValidation() = runBlocking {
        val authenticator = CtapAuthenticator(extensionProcessors = listOf(LargeBlobKeyExtensionProcessor()))
        val session = authenticator.createSession()
        val protocol = session.pinUvAuthManager.pinUvAuthProtocols.first()
        val reader = authenticator.createSession()
        suspend fun read(): ByteArray = reader.invokeCommand<AuthenticatorLargeBlobsRequest, AuthenticatorLargeBlobsResponse>(
            AuthenticatorLargeBlobsRequest(100, null, 0, null, null, null)
        ).responseData!!.config
        suspend fun write(offset: Int, bytes: ByteArray, length: Int?): CtapStatusCode {
            val message = ByteArray(32) { -1 } + byteArrayOf(12, 0) +
                ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(offset).array() +
                MessageDigest.getInstance("SHA-256").digest(bytes)
            return session.invokeCommand<AuthenticatorLargeBlobsRequest, AuthenticatorLargeBlobsResponse>(
                AuthenticatorLargeBlobsRequest(null, bytes, offset, length,
                    protocol.authenticate(protocol.pinUvAuthToken, message), protocol.version)
            ).statusCode
        }
        val initial = read()
        val array = byteArrayOf(0x81.toByte(), 1)
        val checksum = MessageDigest.getInstance("SHA-256").digest(array).copyOf(16)
        val length = array.size + checksum.size
        protocol.tokenState.beginUsingPinUvAuthToken(true)
        protocol.tokenState.permissions = PinUvAuthTokenPermissions(PinUvAuthTokenPermission.GA)
        assertEquals(CtapStatusCode.CTAP2_ERR_PIN_AUTH_INVALID, write(0, array, length))
        protocol.tokenState.permissions = PinUvAuthTokenPermissions(PinUvAuthTokenPermission.LBW)
        assertEquals(CtapStatusCode.CTAP2_OK, write(0, array, length))
        assertArrayEquals(initial, read())
        assertEquals(CtapStatusCode.CTAP2_ERR_INTEGRITY_FAILURE, write(array.size, ByteArray(16), null))
        assertArrayEquals(initial, read())
        assertEquals(CtapStatusCode.CTAP2_OK, write(0, array, length))
        assertEquals(CtapStatusCode.CTAP2_OK, write(array.size, checksum, null))
        assertArrayEquals(array + checksum, read())
    }
}
