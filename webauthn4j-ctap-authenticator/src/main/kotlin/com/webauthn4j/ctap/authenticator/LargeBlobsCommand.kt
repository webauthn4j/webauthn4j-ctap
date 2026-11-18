package com.webauthn4j.ctap.authenticator

import com.webauthn4j.ctap.authenticator.data.settings.AlwaysUvSetting
import com.webauthn4j.ctap.authenticator.store.LargeBlobArrayStore
import com.webauthn4j.ctap.core.data.*
import com.webauthn4j.ctap.core.data.CtapStatusCode.Companion as Status
import com.webauthn4j.ctap.core.data.options.UserVerificationOption
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest

internal class LargeBlobsCommand(private val session: CtapAuthenticatorSession) {
    companion object {
        const val CAPACITY = 65536
        const val MAX_MESSAGE_SIZE = 2048
        private const val MAX_FRAGMENT = MAX_MESSAGE_SIZE - 64
    }

    private var pending: ByteArray? = null
    private var nextOffset = 0

    fun execute(request: AuthenticatorLargeBlobsRequest): AuthenticatorLargeBlobsResponse {
        if (session.largeBlobKeyProcessor == null) return AuthenticatorLargeBlobsResponse(Status.CTAP1_ERR_INVALID_COMMAND)
        val store = session.authenticatorPropertyStore as LargeBlobArrayStore
        val invalid = Status.CTAP1_ERR_INVALID_PARAMETER
        val offset = request.offset ?: return AuthenticatorLargeBlobsResponse(invalid)
        if (offset < 0 || (request.get == null) == (request.set == null)) return AuthenticatorLargeBlobsResponse(invalid)
        request.get?.let { count ->
            if (count < 0 || request.length != null || request.pinUvAuthParam != null || request.pinUvAuthProtocol != null)
                return AuthenticatorLargeBlobsResponse(invalid)
            if (count > MAX_FRAGMENT) return AuthenticatorLargeBlobsResponse(Status.CTAP1_ERR_INVALID_LENGTH)
            val data = store.serializedLargeBlobArray
            if (offset > data.size) return AuthenticatorLargeBlobsResponse(invalid)
            val fragment = data.copyOfRange(offset, minOf(offset + count, data.size))
            return AuthenticatorLargeBlobsResponse(Status.CTAP2_OK, AuthenticatorLargeBlobsResponseData(fragment))
        }

        val fragment = requireNotNull(request.set)
        if (fragment.size > MAX_FRAGMENT) return AuthenticatorLargeBlobsResponse(Status.CTAP1_ERR_INVALID_LENGTH)
        if ((offset == 0) != (request.length != null)) return AuthenticatorLargeBlobsResponse(invalid)
        val size = request.length ?: pending?.size ?: return AuthenticatorLargeBlobsResponse(Status.CTAP1_ERR_INVALID_SEQ)
        if (size < 17) return AuthenticatorLargeBlobsResponse(invalid)
        if (size > CAPACITY) return AuthenticatorLargeBlobsResponse(Status.CTAP2_ERR_LARGE_BLOB_STORAGE_FULL)
        if (offset != 0 && offset != nextOffset) return AuthenticatorLargeBlobsResponse(Status.CTAP1_ERR_INVALID_SEQ)
        if (offset > size - fragment.size) return AuthenticatorLargeBlobsResponse(invalid)
        val authError = authorizeWrite(request, offset, fragment)
        if (authError != null) return AuthenticatorLargeBlobsResponse(authError)

        val buffer = if (offset == 0) ByteArray(size).also { pending = it } else requireNotNull(pending)
        fragment.copyInto(buffer, offset)
        nextOffset = offset + fragment.size
        if (nextOffset == size) {
            pending = null
            nextOffset = 0
            val digest = MessageDigest.getInstance("SHA-256")
            digest.update(buffer, 0, size - 16)
            if (!digest.digest().copyOf(16).contentEquals(buffer.copyOfRange(size - 16, size)))
                return AuthenticatorLargeBlobsResponse(Status.CTAP2_ERR_INTEGRITY_FAILURE)
            store.serializedLargeBlobArray = buffer
        }
        return AuthenticatorLargeBlobsResponse(Status.CTAP2_OK)
    }

    private fun authorizeWrite(request: AuthenticatorLargeBlobsRequest, offset: Int, fragment: ByteArray): CtapStatusCode? {
        if (session.alwaysUv != AlwaysUvSetting.ENABLED && !session.isClientPINReady &&
            session.userVerificationCapabilityProvider.getUserVerificationOption(null) != UserVerificationOption.READY) return null
        val param = request.pinUvAuthParam ?: return Status.CTAP2_ERR_PUAT_REQUIRED
        val version = request.pinUvAuthProtocol ?: return Status.CTAP2_ERR_MISSING_PARAMETER
        val protocol = session.pinUvAuthManager.pinUvAuthProtocols.find { it.version == version } ?: return Status.CTAP1_ERR_INVALID_PARAMETER
        val message = ByteArray(32) { 0xff.toByte() } + byteArrayOf(0x0c, 0) +
            ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(offset).array() +
            MessageDigest.getInstance("SHA-256").digest(fragment)
        if (!protocol.tokenState.isInUse() || !protocol.tokenState.hasPermission(PinUvAuthTokenPermission.LBW) ||
            !protocol.verify(protocol.pinUvAuthToken, message, param)) return Status.CTAP2_ERR_PIN_AUTH_INVALID
        return null
    }
}
