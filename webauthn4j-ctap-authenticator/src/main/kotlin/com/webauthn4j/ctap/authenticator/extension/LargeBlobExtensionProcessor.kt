package com.webauthn4j.ctap.authenticator.extension

import com.webauthn4j.ctap.authenticator.UserCredentialBuilder
import com.webauthn4j.ctap.authenticator.data.credential.LargeBlobData
import com.webauthn4j.ctap.authenticator.data.credential.ResidentUserCredential
import com.webauthn4j.ctap.authenticator.execution.CtapCommandExecutionException
import com.webauthn4j.ctap.core.data.CtapStatusCode

/**
 * CTAP 2.3 section 12.4 inline largeBlob extension.
 * Blob bytes are opaque to the authenticator and never enter signed authenticator data.
 * Register a separate instance for each authenticator's extension list.
 */
class LargeBlobExtensionProcessor(private val maxCompressedSize: Int = 65536) :
    RegistrationUnsignedExtensionProcessor, AuthenticationUnsignedExtensionProcessor {

    override val extensionId: String = "largeBlob"

    init {
        require(maxCompressedSize > 0)
    }

    override fun processRegistration(
        context: RegistrationExtensionContext,
        builder: UserCredentialBuilder,
    ): Any? {
        val raw = context.makeCredentialRequest.extensions?.getValue(extensionId) ?: return null
        val input = raw as? Map<*, *> ?: invalid()
        if (input.keys != setOf("support") || input["support"] !in listOf("preferred", "required")) {
            invalid()
        }
        if (context.makeCredentialRequest.options?.rk != true) {
            if (input["support"] == "required") {
                throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_LARGE_BLOB_STORAGE_FULL)
            }
            return null
        }
        builder.details().entry(SUPPORT_KEY, "true")
        return mapOf("supported" to true)
    }

    override fun processAuthentication(context: AuthenticationExtensionContext): Any? {
        val raw = context.getAssertionRequest.extensions?.getValue(extensionId) ?: return null
        val input = raw as? Map<*, *> ?: invalid()
        val credential = context.credential as? ResidentUserCredential
        if (input.keys == setOf("read") && input["read"] == true) {
            val blob = credential?.largeBlob ?: return null
            return mapOf("blob" to blob.compressed, "originalSize" to blob.originalSize)
        }
        if (input.keys != setOf("write", "originalSize")) invalid()
        val data = input["write"] as? ByteArray ?: invalid()
        val originalSize = when (val size = input["originalSize"]) {
            is Int -> size.toLong()
            is Long -> size
            else -> invalid()
        }
        if (originalSize < 0) invalid()
        if (context.getAssertionRequest.allowList.isNullOrEmpty() || credential == null ||
            credential.details[SUPPORT_KEY] != "true" || data.size > maxCompressedSize
        ) {
            return mapOf("written" to false)
        }
        credential.largeBlob = LargeBlobData(data, originalSize)
        return mapOf("written" to true)
    }

    private fun invalid(): Nothing =
        throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_INVALID_CBOR)

    companion object {
        private const val SUPPORT_KEY = "webauthn4j.largeBlob.supported"
    }
}
