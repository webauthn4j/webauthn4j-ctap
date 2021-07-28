package com.unifidokey.core.config

import com.webauthn4j.ctap.authenticator.ClientPINService

class PINRetriesConfigProperty internal constructor(configManager: ConfigManager) :
    ConfigPropertyBase<Int>(configManager, KEY, ClientPINService.MAX_PIN_RETRIES) {

    override fun save(value: Int) {
        configManager.persistenceAdaptor.savePrimitiveInt(KEY, value)
    }

    @Throws(ConfigNotFoundException::class)
    override fun load(): Int {
        return configManager.persistenceAdaptor.loadPrimitiveInt(KEY)
    }

    fun reset() {
        value = ClientPINService.MAX_PIN_RETRIES
    }

    companion object {
        const val KEY = "pinRetries"
    }
}