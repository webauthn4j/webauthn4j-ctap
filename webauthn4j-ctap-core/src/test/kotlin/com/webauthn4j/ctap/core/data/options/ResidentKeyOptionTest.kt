package com.webauthn4j.ctap.core.data.options

import org.assertj.core.api.Assertions
import org.junit.jupiter.api.Test

internal class ResidentKeyOptionTest {
    @Test
    fun equals_test() {
        Assertions.assertThat(ResidentKeyOption.SUPPORTED).isEqualTo(ResidentKeyOption.create(true))
        Assertions.assertThat(ResidentKeyOption.NOT_SUPPORTED)
            .isEqualTo(ResidentKeyOption.create(false))
        Assertions.assertThat(ResidentKeyOption.NULL).isEqualTo(ResidentKeyOption.create(null))
        Assertions.assertThat(ResidentKeyOption.create(true))
            .isEqualTo(ResidentKeyOption.create(true))
        Assertions.assertThat(ResidentKeyOption.create(true))
            .isNotEqualTo(ResidentKeyOption.create(false))
        Assertions.assertThat(ResidentKeyOption.create(true))
            .isNotEqualTo(ResidentKeyOption.create(null))
        Assertions.assertThat(ResidentKeyOption.create(false))
            .isEqualTo(ResidentKeyOption.create(false))
        Assertions.assertThat(ResidentKeyOption.create(false))
            .isNotEqualTo(ResidentKeyOption.create(null))
        Assertions.assertThat(ResidentKeyOption.create(null))
            .isEqualTo(ResidentKeyOption.create(null))
    }
}