package com.unifidokey.core.config

import com.webauthn4j.ctap.authenticator.settings.ConsentCachingSetting

class ConsentCachingConfigProperty internal constructor(configManager: ConfigManager) :
    ConfigPropertyBase<ConsentCachingSetting>(configManager, KEY, ConsentCachingSetting.ENABLED) {

    override fun save(value: ConsentCachingSetting) {
        configManager.persistenceAdaptor.savePrimitiveBoolean(KEY, value.value)
    }

    @Throws(ConfigNotFoundException::class)
    override fun load(): ConsentCachingSetting {
        return ConsentCachingSetting.create(configManager.persistenceAdaptor.loadPrimitiveBoolean(KEY))
    }

    companion object {
        const val KEY = "consentCaching"
    }
}
