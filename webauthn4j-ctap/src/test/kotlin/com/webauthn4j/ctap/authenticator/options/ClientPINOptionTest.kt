package com.webauthn4j.ctap.authenticator.options

import com.webauthn4j.ctap.authenticator.options.ClientPINOption.Companion.create
import org.assertj.core.api.Assertions
import org.junit.jupiter.api.Test

class ClientPINOptionTest {
    @Test
    fun equals_test() {
        Assertions.assertThat(ClientPINOption.SET).isEqualTo(create(true))
        Assertions.assertThat(ClientPINOption.NOT_SET).isEqualTo(create(false))
        Assertions.assertThat(ClientPINOption.NOT_SUPPORTED).isEqualTo(create(null))
        Assertions.assertThat(create(true)).isEqualTo(create(true))
        Assertions.assertThat(create(true)).isNotEqualTo(create(false))
        Assertions.assertThat(create(true)).isNotEqualTo(create(null))
        Assertions.assertThat(create(false)).isEqualTo(create(false))
        Assertions.assertThat(create(false)).isNotEqualTo(create(null))
        Assertions.assertThat(create(null)).isEqualTo(create(null))
    }
}