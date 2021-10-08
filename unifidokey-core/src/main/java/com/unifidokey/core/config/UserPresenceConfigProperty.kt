package com.unifidokey.core.config

import com.webauthn4j.ctap.authenticator.data.settings.UserPresenceSetting
import com.webauthn4j.ctap.authenticator.data.settings.UserPresenceSetting.Companion.create

class UserPresenceConfigProperty internal constructor(configManager: ConfigManager) :
    ConfigPropertyBase<UserPresenceSetting>(configManager, KEY, UserPresenceSetting.SUPPORTED) {

    override fun save(value: UserPresenceSetting) {
        configManager.persistenceAdaptor.saveString(KEY, value.value)
    }

    @Throws(ConfigNotFoundException::class)
    override fun load(): UserPresenceSetting {
        return create(configManager.persistenceAdaptor.loadString(KEY))
    }

    companion object {
        const val KEY = "userPresence"
    }
}