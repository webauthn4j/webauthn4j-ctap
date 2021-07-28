package com.webauthn4j.ctap.authenticator.settings

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Assertions.assertAll
import org.junit.jupiter.api.Test

internal class ResetProtectionSettingTest {

    @Test
    fun create_test() {
        assertAll(
            { assertThat(ResetProtectionSetting.create(true)).isEqualTo(ResetProtectionSetting.ENABLED) },
            { assertThat(ResetProtectionSetting.create(false)).isEqualTo(ResetProtectionSetting.DISABLED) },
        )
    }

}