package com.unifidokey.core.config

import com.webauthn4j.ctap.authenticator.settings.PlatformSetting
import com.webauthn4j.ctap.authenticator.settings.PlatformSetting.Companion.create

class PlatformConfigProperty internal constructor(configManager: ConfigManager) :
    ConfigPropertyBase<PlatformSetting>(configManager, KEY, PlatformSetting.CROSS_PLATFORM) {

    override fun save(value: PlatformSetting) {
        configManager.persistenceAdaptor.saveString(KEY, value.value)
    }

    @Throws(ConfigNotFoundException::class)
    override fun load(): PlatformSetting {
        return create(configManager.persistenceAdaptor.loadString(KEY))
    }

    companion object {
        const val KEY = "platform"
    }
}
