package com.webauthn4j.ctap.core.util

import com.webauthn4j.ctap.core.util.internal.BooleanUtil
import org.assertj.core.api.Assertions
import org.junit.jupiter.api.Test

internal class BooleanUtilTest {
    @Test
    fun isTrue() {
        Assertions.assertThat(BooleanUtil.isTrue(true)).isTrue
        Assertions.assertThat(BooleanUtil.isTrue(false)).isFalse
        Assertions.assertThat(BooleanUtil.isTrue(null)).isFalse
    }

    @Test
    fun isNotTrue() {
        Assertions.assertThat(BooleanUtil.isNotTrue(true)).isFalse
        Assertions.assertThat(BooleanUtil.isNotTrue(false)).isTrue
        Assertions.assertThat(BooleanUtil.isNotTrue(null)).isTrue
    }
}