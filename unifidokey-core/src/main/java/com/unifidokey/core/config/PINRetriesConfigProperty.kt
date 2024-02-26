package com.unifidokey.core.config

import com.webauthn4j.ctap.authenticator.ClientPINService

class PINRetriesConfigProperty internal constructor(configManager: ConfigManager) :
    ConfigPropertyBase<UInt>(configManager, KEY, ClientPINService.MAX_PIN_RETRIES, ReleaseLevel.PRIVATE, false, false) {

    override fun save(value: UInt) {
        configManager.persistenceAdaptor.savePrimitiveInt(KEY, value.toInt())
    }

    @Throws(ConfigNotFoundException::class)
    override fun load(): UInt {
        return configManager.persistenceAdaptor.loadPrimitiveInt(KEY).toUInt()
    }

    companion object {
        const val KEY = "pinRetries"
    }
}