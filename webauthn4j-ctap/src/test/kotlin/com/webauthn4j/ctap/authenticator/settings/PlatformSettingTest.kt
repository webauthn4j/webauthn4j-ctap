package com.webauthn4j.ctap.authenticator.settings

import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Assertions.assertAll
import org.junit.jupiter.api.Test

internal class PlatformSettingTest {

    @Test
    fun create_test() {
        assertAll(
            { assertThat(PlatformSetting.create("cross-platform")).isEqualTo(PlatformSetting.CROSS_PLATFORM) },
            { assertThat(PlatformSetting.create("platform")).isEqualTo(PlatformSetting.PLATFORM) },
            {
                assertThatThrownBy { PlatformSetting.create("invalid") }.isInstanceOf(
                    IllegalArgumentException::class.java
                )
            },
        )
    }

}