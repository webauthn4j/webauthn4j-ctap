package com.unifidokey.core.config

import com.fasterxml.jackson.core.type.TypeReference
import com.webauthn4j.converter.util.CborConverter
import com.webauthn4j.converter.util.ObjectConverter
import java.security.cert.X509Certificate

class CACertificatesConfigProperty internal constructor(configManager: ConfigManager) :
    ConfigPropertyBase<List<X509Certificate>?>(configManager, KEY, null) {

    private val cborConverter: CborConverter = ObjectConverter().cborConverter

    override fun save(value: List<X509Certificate>?) {
        val bytes = cborConverter.writeValueAsBytes(value)
        configManager.persistenceAdaptor.saveBytes(KEY, bytes)
    }

    @Throws(ConfigNotFoundException::class)
    override fun load(): List<X509Certificate>? {
        val bytes = configManager.persistenceAdaptor.loadBytes(KEY)
        return cborConverter.readValue(bytes, object : TypeReference<List<X509Certificate>>() {})
    }

    companion object {
        const val KEY = "caCertificates"
    }

}
