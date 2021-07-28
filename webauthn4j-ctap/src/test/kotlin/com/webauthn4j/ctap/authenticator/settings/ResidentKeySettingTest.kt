package com.webauthn4j.ctap.authenticator.settings

import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Assertions.assertAll
import org.junit.jupiter.api.Test

internal class ResidentKeySettingTest {

    @Test
    fun create_test() {
        assertAll(
            { assertThat(ResidentKeySetting.create("always")).isEqualTo(ResidentKeySetting.ALWAYS) },
            { assertThat(ResidentKeySetting.create("if-required")).isEqualTo(ResidentKeySetting.IF_REQUIRED) },
            { assertThat(ResidentKeySetting.create("never")).isEqualTo(ResidentKeySetting.NEVER) },
            {
                assertThatThrownBy { ResidentKeySetting.create("invalid") }.isInstanceOf(
                    IllegalArgumentException::class.java
                )
            },
        )
    }

}