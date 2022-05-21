package com.webauthn4j.ctap.core.util

import com.webauthn4j.ctap.core.util.internal.KeyAgreementUtil
import com.webauthn4j.util.ECUtil
import org.assertj.core.api.Assertions
import org.junit.jupiter.api.Test
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey

internal class KeyAgreementUtilTest {
    @Test
    fun generateSecret_test() {
        val authenticatorKeyPair = ECUtil.createKeyPair()
        val platformKeyPair = ECUtil.createKeyPair()
        val derivedSharedSecretOnAuthenticator = KeyAgreementUtil.generateSecret(
            authenticatorKeyPair.private as ECPrivateKey,
            platformKeyPair.public as ECPublicKey
        )
        val derivedSharedSecretOnPlatform = KeyAgreementUtil.generateSecret(
            platformKeyPair.private as ECPrivateKey,
            authenticatorKeyPair.public as ECPublicKey
        )
        Assertions.assertThat(derivedSharedSecretOnAuthenticator)
            .isEqualTo(derivedSharedSecretOnPlatform)
    }
}