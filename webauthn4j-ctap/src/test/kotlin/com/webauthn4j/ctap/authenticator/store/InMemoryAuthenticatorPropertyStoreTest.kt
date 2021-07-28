package com.webauthn4j.ctap.authenticator.store

import org.assertj.core.api.Assertions
import org.junit.jupiter.api.Test
import java.io.Serializable

internal class InMemoryAuthenticatorPropertyStoreTest {
    private val target = InMemoryAuthenticatorPropertyStore<Serializable>()

    @Test
    fun loadCredentialSourceEncryptionIV_test() {
        val iv = target.loadEncryptionIV()
        Assertions.assertThat(iv).isNotNull
    }
}