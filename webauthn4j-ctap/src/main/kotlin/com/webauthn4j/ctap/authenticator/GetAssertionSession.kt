package com.webauthn4j.ctap.authenticator

import com.webauthn4j.ctap.authenticator.store.UserCredential
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionAuthenticatorOutput
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorOutputs
import com.webauthn4j.util.MessageDigestUtil
import java.nio.charset.StandardCharsets
import java.time.Instant

class GetAssertionSession(
    val assertionObjects: List<AssertionObject>,
    clientDataHash: ByteArray,
    rpId: String
) {
    private var index = 0
    private var instant: Instant
    val clientDataHash: ByteArray
    val rpId: String

    init {
        instant = Instant.now()
        this.clientDataHash = clientDataHash
        this.rpId = rpId
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

    val rpIdHash: ByteArray
        get() = MessageDigestUtil.createSHA256().digest(rpId.toByteArray(StandardCharsets.UTF_8))

    fun withAssertionObjects(assertionObjects: List<AssertionObject>): GetAssertionSession {
        return GetAssertionSession(assertionObjects, clientDataHash, rpId)
    }

    data class AssertionObject(var userCredential: UserCredential, var extensions: AuthenticationExtensionsAuthenticatorOutputs<AuthenticationExtensionAuthenticatorOutput>, var flags: Byte) {
    }

}