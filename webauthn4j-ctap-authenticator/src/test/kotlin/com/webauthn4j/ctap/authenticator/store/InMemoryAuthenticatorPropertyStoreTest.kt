package com.webauthn4j.ctap.authenticator.store

import org.assertj.core.api.Assertions
import org.junit.jupiter.api.Test

internal class InMemoryAuthenticatorPropertyStoreTest {
    private val target = InMemoryAuthenticatorPropertyStore()

    @Test
    fun loadCredentialSourceEncryptionIV_test() {
        val iv = target.loadEncryptionIV()
        Assertions.assertThat(iv).isNotNull
    }
}