package com.webauthn4j.ctap.authenticator.settings

import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Assertions.assertAll
import org.junit.jupiter.api.Test

internal class UserVerificationSettingTest {

    @Test
    fun create_test() {
        assertAll(
            { assertThat(UserVerificationSetting.create("ready")).isEqualTo(UserVerificationSetting.READY) },
            {
                assertThat(UserVerificationSetting.create("not-ready")).isEqualTo(
                    UserVerificationSetting.NOT_READY
                )
            },
            {
                assertThat(UserVerificationSetting.create("not-supported")).isEqualTo(
                    UserVerificationSetting.NOT_SUPPORTED
                )
            },
            {
                assertThatThrownBy { UserVerificationSetting.create("invalid") }.isInstanceOf(
                    IllegalArgumentException::class.java
                )
            },
        )
    }

}