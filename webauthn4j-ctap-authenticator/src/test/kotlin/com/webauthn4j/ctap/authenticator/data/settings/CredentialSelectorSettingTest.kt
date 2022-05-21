package com.webauthn4j.ctap.authenticator.data.settings

import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Assertions.assertAll
import org.junit.jupiter.api.Test

internal class CredentialSelectorSettingTest {

    @Test
    fun create_test() {
        assertAll(
            {
                assertThat(CredentialSelectorSetting.create("authenticator")).isEqualTo(
                    CredentialSelectorSetting.AUTHENTICATOR
                )
            },
            {
                assertThat(CredentialSelectorSetting.create("client-platform")).isEqualTo(
                    CredentialSelectorSetting.CLIENT_PLATFORM
                )
            },
            {
                assertThatThrownBy { CredentialSelectorSetting.create("invalid") }.isInstanceOf(
                    IllegalArgumentException::class.java
                )
            },
        )
    }

}
