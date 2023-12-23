package com.unifidokey.core.config

import com.webauthn4j.ctap.authenticator.data.settings.ResidentKeySetting
import com.webauthn4j.ctap.authenticator.data.settings.ResidentKeySetting.Companion.create

class ResidentKeyConfigProperty internal constructor(configManager: ConfigManager) :
    ConfigPropertyBase<ResidentKeySetting>(configManager, KEY, ResidentKeySetting.IF_REQUIRED, false, false, true) {

    override fun save(value: ResidentKeySetting) {
        configManager.persistenceAdaptor.saveString(KEY, value.value)
    }

    @Throws(ConfigNotFoundException::class)
    override fun load(): ResidentKeySetting {
        return create(configManager.persistenceAdaptor.loadString(KEY))
    }

    companion object {
        const val KEY = "residentKey"
    }
}
