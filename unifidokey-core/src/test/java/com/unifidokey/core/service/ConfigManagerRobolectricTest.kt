package com.unifidokey.core.service

import com.google.common.truth.Truth.assertThat
import com.unifidokey.core.adapter.InMemoryPersistenceAdaptor
import com.unifidokey.core.config.ConfigManager
import com.webauthn4j.data.attestation.authenticator.AAGUID
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.util.*

@RunWith(RobolectricTestRunner::class)
internal class ConfigManagerRobolectricTest {

    private val target: ConfigManager = ConfigManager(InMemoryPersistenceAdaptor())

    init {
        target.setup()
    }

    @Test
    fun aaguid_test() {
        val value = AAGUID(UUID.randomUUID())
        target.aaguid.value = value
        val retrieved = target.aaguid.value
        assertThat(retrieved).isEqualTo(value)
    }

    @Test
    fun clientPINEnc_test() {
        val value = byteArrayOf(0x01, 0x23)
        target.clientPINEnc.value = value
        val retrieved = target.clientPINEnc.value
        assertThat(retrieved).isEqualTo(value)
    }

    @Test
    fun pinRetries_test() {
        val value = 1u
        target.pinRetries.value = value
        val retrieved: UInt = target.pinRetries.value
        assertThat(retrieved).isEqualTo(value)
    }

    @Test
    fun bleEnabled_test() {
        val value = true
        target.isBLETransportEnabled.value = value
        val retrieved = target.isBLETransportEnabled.value
        assertThat(retrieved).isEqualTo(value)
    }

    @Test
    fun credentialSourceEncryptionIV_test() {
        val data = byteArrayOf(0x01, 0x23)
        target.credentialSourceEncryptionIV.value = data
        val retrieved = target.credentialSourceEncryptionIV.value
        assertThat(retrieved).isEqualTo(data)
    }

    @Test
    fun credentialSourceEncryptionIV_multiple_load_test() {
        val retrieved0 = target.credentialSourceEncryptionIV.value
        val retrieved1 = target.credentialSourceEncryptionIV.value
        assertThat(retrieved0).isEqualTo(retrieved1)
    }
}