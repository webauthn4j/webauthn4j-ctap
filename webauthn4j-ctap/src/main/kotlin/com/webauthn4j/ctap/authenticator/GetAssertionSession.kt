package com.webauthn4j.ctap.authenticator

import com.webauthn4j.ctap.authenticator.store.UserCredential
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionAuthenticatorOutput
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorOutputs
import com.webauthn4j.util.MessageDigestUtil
import java.io.Serializable
import java.nio.charset.StandardCharsets
import java.time.Instant

class GetAssertionSession(
    val userCredentials: List<UserCredential<Serializable?>>,
    clientDataHash: ByteArray,
    rpId: String,
    flags: Byte,
    extensions: AuthenticationExtensionsAuthenticatorOutputs<AuthenticationExtensionAuthenticatorOutput>
) {
    private var userCredentialIndex = 0
    private var instant: Instant
    val clientDataHash: ByteArray
    val rpId: String
    val flags: Byte
    val extensions: AuthenticationExtensionsAuthenticatorOutputs<AuthenticationExtensionAuthenticatorOutput>

    init {
        instant = Instant.now()
        this.clientDataHash = clientDataHash
        this.rpId = rpId
        this.flags = flags
        this.extensions = extensions
    }

    fun nextUserCredential(): UserCredential<Serializable?> {
        if (userCredentials.size <= userCredentialIndex) {
            throw NoSuchElementException()
        }
        val userCredential = userCredentials[userCredentialIndex]
        userCredentialIndex++
        return userCredential
    }

    val numberOfCredentials: Int
        get() = userCredentials.size

    fun resetTimer(): Instant {
        return Instant.now().also { instant = it }
    }

    fun isExpired(): Boolean {
        return Instant.now().epochSecond - instant.epochSecond >= 30
    }

    val rpIdHash: ByteArray
        get() = MessageDigestUtil.createSHA256().digest(rpId.toByteArray(StandardCharsets.UTF_8))

    fun withUserCredentials(userCredentials: List<UserCredential<Serializable?>>): GetAssertionSession {
        return GetAssertionSession(userCredentials, clientDataHash, rpId, flags, extensions)
    }

}