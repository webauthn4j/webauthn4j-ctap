package com.webauthn4j.ctap.authenticator.settings

import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Assertions.assertAll
import org.junit.jupiter.api.Test

internal class UserPresenceSettingTest {

    @Test
    fun create_test() {
        assertAll(
            { assertThat(UserPresenceSetting.create("supported")).isEqualTo(UserPresenceSetting.SUPPORTED) },
            { assertThat(UserPresenceSetting.create("not-supported")).isEqualTo(UserPresenceSetting.NOT_SUPPORTED) },
            {
                assertThatThrownBy { UserPresenceSetting.create("invalid") }.isInstanceOf(
                    IllegalArgumentException::class.java
                )
            },
        )
    }

}