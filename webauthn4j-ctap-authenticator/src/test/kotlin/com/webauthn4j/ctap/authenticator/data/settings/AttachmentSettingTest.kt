package com.webauthn4j.ctap.authenticator.data.settings

import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Assertions.assertAll
import org.junit.jupiter.api.Test

internal class AttachmentSettingTest {

    @Test
    fun create_test() {
        assertAll(
            { assertThat(AttachmentSetting.create("cross-platform")).isEqualTo(AttachmentSetting.CROSS_PLATFORM) },
            { assertThat(AttachmentSetting.create("platform")).isEqualTo(AttachmentSetting.PLATFORM) },
            {
                assertThatThrownBy { AttachmentSetting.create("invalid") }.isInstanceOf(
                    IllegalArgumentException::class.java
                )
            },
        )
    }

}