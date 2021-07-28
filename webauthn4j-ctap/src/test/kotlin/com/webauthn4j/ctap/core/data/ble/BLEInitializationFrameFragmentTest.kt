package com.webauthn4j.ctap.core.data.ble

import com.webauthn4j.ctap.core.data.ble.BLEInitializationFrameFragment.Companion.parse
import com.webauthn4j.util.Base64UrlUtil
import org.assertj.core.api.Assertions
import org.junit.jupiter.api.Test

internal class BLEInitializationFrameFragmentTest {
    @Test
    fun test() {
        @Suppress("SpellCheckingInspection")
        val data: ByteArray = Base64UrlUtil.decode("gwFtAaUBWCA8cFwsrhxkHiTchwx8Tw-OJvBFJ9ke0SaZwNGK3bSaTwKiYmlka3dlYmF1dGhuLmlvZG5hbWVrd2ViYXV0aG4uaW8Do2JpZErK1QQAAAAAAAAAZG5hbWVwbWFpbEB5bm9qaW1hLm5ldGtkaXNwbGF5TmFtZWRtYWlsBIqiY2FsZyZkdHlwZWpwdWJsaWMta2V5omNhbGc4ImR0eXBlanB1YmxpYy1rZXmiY2FsZzgjZHR5cGVqcHVibGljLWtleaJjYWxnOQEAZHR5cGVqcHVibGljLWtleaJjYWxnOQEBZHR5cGVqcHVibGljLWtleaJjYWxnOQECZA")
        val bleFrameFragment = parse(data)
        Assertions.assertThat(bleFrameFragment.cmd).isEqualTo(BLEFrameCommand.MSG)
        Assertions.assertThat(bleFrameFragment.length).isEqualTo(365)
        Assertions.assertThat(bleFrameFragment.data.size).isEqualTo(253)
    }
}
