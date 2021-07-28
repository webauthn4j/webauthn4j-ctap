package com.webauthn4j.ctap.authenticator.options

import com.webauthn4j.converter.util.ObjectConverter
import org.assertj.core.api.Assertions
import org.junit.jupiter.api.Test

internal class UserVerificationOptionTest {
    @Test
    fun equals_test() {
        Assertions.assertThat(UserVerificationOption.READY)
            .isEqualTo(UserVerificationOption.create(true))
        Assertions.assertThat(UserVerificationOption.NOT_READY)
            .isEqualTo(UserVerificationOption.create(false))
        Assertions.assertThat(UserVerificationOption.NOT_SUPPORTED)
            .isEqualTo(UserVerificationOption.create(null))
        Assertions.assertThat(UserVerificationOption.create(true))
            .isEqualTo(UserVerificationOption.create(true))
        Assertions.assertThat(UserVerificationOption.create(true))
            .isNotEqualTo(UserVerificationOption.create(false))
        Assertions.assertThat(UserVerificationOption.create(true))
            .isNotEqualTo(UserVerificationOption.create(null))
        Assertions.assertThat(UserVerificationOption.create(false))
            .isEqualTo(UserVerificationOption.create(false))
        Assertions.assertThat(UserVerificationOption.create(false))
            .isNotEqualTo(UserVerificationOption.create(null))
        Assertions.assertThat(UserVerificationOption.create(null))
            .isEqualTo(UserVerificationOption.create(null))
    }

    @Test
    fun deserialize_test() {
        @Suppress("JoinDeclarationAndAssignment")
        var dto: DTO?
        dto = ObjectConverter().jsonConverter.readValue("{ \"uv\":true }", DTO::class.java)
        Assertions.assertThat(dto!!.uv).isEqualTo(UserVerificationOption.READY)
        dto = ObjectConverter().jsonConverter.readValue("{ \"uv\":false }", DTO::class.java)
        Assertions.assertThat(dto!!.uv).isEqualTo(UserVerificationOption.NOT_READY)
        dto = ObjectConverter().jsonConverter.readValue("{ \"uv\":null }", DTO::class.java)
        Assertions.assertThat(dto!!.uv).isEqualTo(UserVerificationOption.NOT_SUPPORTED)
    }

    internal class DTO {
        var uv: UserVerificationOption? = null
    }
}