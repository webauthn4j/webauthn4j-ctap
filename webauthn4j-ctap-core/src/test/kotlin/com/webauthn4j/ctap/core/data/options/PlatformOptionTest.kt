package com.webauthn4j.ctap.core.data.options

import org.assertj.core.api.Assertions
import org.junit.jupiter.api.Test

internal class PlatformOptionTest {
    @Test
    fun equals_test() {
        Assertions.assertThat(PlatformOption.PLATFORM).isEqualTo(PlatformOption.create(true))
        Assertions.assertThat(PlatformOption.CROSS_PLATFORM).isEqualTo(PlatformOption.create(false))
        Assertions.assertThat(PlatformOption.NULL).isEqualTo(PlatformOption.create(null))
        Assertions.assertThat(PlatformOption.create(true)).isEqualTo(PlatformOption.create(true))
        Assertions.assertThat(PlatformOption.create(true))
            .isNotEqualTo(PlatformOption.create(false))
        Assertions.assertThat(PlatformOption.create(true)).isNotEqualTo(PlatformOption.create(null))
        Assertions.assertThat(PlatformOption.create(false)).isEqualTo(PlatformOption.create(false))
        Assertions.assertThat(PlatformOption.create(false))
            .isNotEqualTo(PlatformOption.create(null))
        Assertions.assertThat(PlatformOption.create(null)).isEqualTo(PlatformOption.create(null))
    }
}