package com.webauthn4j.ctap.authenticator.extension

import com.webauthn4j.ctap.authenticator.data.credential.Credential
import com.webauthn4j.ctap.authenticator.data.credential.ResidentUserCredential
import com.webauthn4j.ctap.authenticator.execution.CtapCommandExecutionException
import com.webauthn4j.ctap.core.data.AuthenticatorGetAssertionRequest
import com.webauthn4j.ctap.core.data.AuthenticatorMakeCredentialRequest
import com.webauthn4j.ctap.core.data.CtapStatusCode
import java.security.SecureRandom

class LargeBlobKeyExtensionProcessor : ExtensionProcessor {
    override val extensionId = "largeBlobKey"
    private val random = SecureRandom()

    internal fun register(request: AuthenticatorMakeCredentialRequest): ByteArray? {
        val input = request.extensions?.getValue(extensionId) ?: return null
        if (input != true || request.options?.rk != true) throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_INVALID_OPTION)
        return ByteArray(32).also(random::nextBytes)
    }

    internal fun read(request: AuthenticatorGetAssertionRequest, credential: Credential): ByteArray? {
        val input = request.extensions?.getValue(extensionId) ?: return null
        if (input != true) throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_INVALID_OPTION)
        return (credential as? ResidentUserCredential)?.largeBlobKey
    }
}
