package com.webauthn4j.ctap.authenticator.settings

import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Assertions.assertAll
import org.junit.jupiter.api.Test


internal class AttestationStatementFormatSettingTest {

    @Test
    fun create_test() {
        assertAll(
            {
                assertThat(AttestationStatementFormatSetting.create("android-key")).isEqualTo(
                    AttestationStatementFormatSetting.ANDROID_KEY
                )
            },
            {
                assertThat(AttestationStatementFormatSetting.create("android-safetynet")).isEqualTo(
                    AttestationStatementFormatSetting.ANDROID_SAFETYNET
                )
            },
            {
                assertThat(AttestationStatementFormatSetting.create("packed")).isEqualTo(
                    AttestationStatementFormatSetting.PACKED
                )
            },
            {
                assertThat(AttestationStatementFormatSetting.create("fido-u2f")).isEqualTo(
                    AttestationStatementFormatSetting.FIDO_U2F
                )
            },
            {
                assertThat(AttestationStatementFormatSetting.create("none")).isEqualTo(
                    AttestationStatementFormatSetting.NONE
                )
            },
            {
                assertThatThrownBy { AttestationStatementFormatSetting.create("invalid") }.isInstanceOf(
                    IllegalArgumentException::class.java
                )
            },
        )
    }


}