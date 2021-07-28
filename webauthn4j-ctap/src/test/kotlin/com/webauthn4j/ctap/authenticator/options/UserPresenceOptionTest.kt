package com.webauthn4j.ctap.authenticator.options

import com.webauthn4j.ctap.authenticator.options.UserPresenceOption.Companion.create
import org.assertj.core.api.Assertions
import org.junit.jupiter.api.Test

class UserPresenceOptionTest {
    @Test
    fun equals_test() {
        Assertions.assertThat(UserPresenceOption.SUPPORTED).isEqualTo(create(true))
        Assertions.assertThat(UserPresenceOption.NOT_SUPPORTED).isEqualTo(create(false))
        Assertions.assertThat(UserPresenceOption.NULL).isEqualTo(create(null))
        Assertions.assertThat(create(true)).isEqualTo(create(true))
        Assertions.assertThat(create(true)).isNotEqualTo(create(false))
        Assertions.assertThat(create(true)).isNotEqualTo(create(null))
        Assertions.assertThat(create(false)).isEqualTo(create(false))
        Assertions.assertThat(create(false)).isNotEqualTo(create(null))
        Assertions.assertThat(create(null)).isEqualTo(create(null))
    }
}
