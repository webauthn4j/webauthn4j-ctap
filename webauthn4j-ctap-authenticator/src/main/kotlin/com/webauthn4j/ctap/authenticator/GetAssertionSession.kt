package com.webauthn4j.ctap.authenticator

import com.webauthn4j.ctap.authenticator.data.credential.Credential
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionAuthenticatorOutput
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorOutputs
import java.time.Instant

// Holds the state for an ongoing authenticatorGetAssertion flow, including
// GetNextAssertion iteration. Corresponds to §6.2.2 Step 12.2.2.
class GetAssertionSession(
    // 12.2.2.1: remembered authenticatorGetAssertion parameters
    val assertionObjects: List<AssertionObject>,
    clientDataHash: ByteArray
) {
    // 12.2.2.2: credential counter (zero-based index into assertionObjects)
    private var index = 0
    // 12.2.2.3: timer for GetNextAssertion expiration (30 seconds)
    private var instant: Instant
    val clientDataHash: ByteArray

    init {
        instant = Instant.now()
        this.clientDataHash = clientDataHash
    }

    fun hasNext(): Boolean = index < assertionObjects.size

    fun currentAssertionObject(): AssertionObject {
        if (assertionObjects.size <= index) {
            throw NoSuchElementException()
        }
        return assertionObjects[index]
    }

    fun incrementCredentialCounter() {
        index++
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

    data class AssertionObject(
        var credential: Credential,
        var maskUserIdentifiableInfo: Boolean,
        var extensions: AuthenticationExtensionsAuthenticatorOutputs<AuthenticationExtensionAuthenticatorOutput>,
        var flags: Byte
    )

}