package com.webauthn4j.ctap.authenticator.data.settings

import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Assertions.assertAll
import org.junit.jupiter.api.Test

internal class ClientPINSettingTest {

    @Test
    fun create_test() {
        assertAll(
            { assertThat(ClientPINSetting.create("enabled")).isEqualTo(ClientPINSetting.ENABLED) },
            { assertThat(ClientPINSetting.create("disabled")).isEqualTo(ClientPINSetting.DISABLED) },
            {
                assertThatThrownBy { CredentialSelectorSetting.create("invalid") }.isInstanceOf(
                    IllegalArgumentException::class.java
                )
            },
        )
    }
}
