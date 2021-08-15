package com.webauthn4j.ctap.authenticator

import com.webauthn4j.ctap.authenticator.store.Credential
import com.webauthn4j.ctap.authenticator.store.UserCredential
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionAuthenticatorOutput
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorOutputs
import com.webauthn4j.util.MessageDigestUtil
import java.nio.charset.StandardCharsets
import java.time.Instant

class GetAssertionSession(
    val assertionObjects: List<AssertionObject>,
    clientDataHash: ByteArray
) {
    private var index = 0
    private var instant: Instant
    val clientDataHash: ByteArray

    init {
        instant = Instant.now()
        this.clientDataHash = clientDataHash
    }

    fun nextAssertionObject(): AssertionObject {
        if (assertionObjects.size <= index) {
            throw NoSuchElementException()
        }
        val assertionObject = assertionObjects[index]
        index++
        return assertionObject
    }

    val numberOfAssertionObjects: Int
        get() = assertionObjects.size

    fun resetTimer(): Instant {
        return Instant.now().also { instant = it }
    }

    fun isExpired(): Boolean {
        return Instant.now().epochSecond - instant.epochSecond >= 30
    }

    fun withAssertionObjects(assertionObjects: List<AssertionObject>): GetAssertionSession {
        return GetAssertionSession(assertionObjects, clientDataHash)
    }

    data class AssertionObject(var credential: Credential, var extensions: AuthenticationExtensionsAuthenticatorOutputs<AuthenticationExtensionAuthenticatorOutput>, var flags: Byte) {
    }

}