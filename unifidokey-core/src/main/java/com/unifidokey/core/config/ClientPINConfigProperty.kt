package com.unifidokey.core.config

import com.webauthn4j.ctap.authenticator.settings.ClientPINSetting
import com.webauthn4j.ctap.authenticator.settings.ClientPINSetting.Companion.create

class ClientPINConfigProperty internal constructor(configManager: ConfigManager) :
    ConfigPropertyBase<ClientPINSetting>(configManager, KEY, ClientPINSetting.ENABLED) {

    override fun save(value: ClientPINSetting) {
        configManager.persistenceAdaptor.saveString(KEY, value.value)
    }

    @Throws(ConfigNotFoundException::class)
    override fun load(): ClientPINSetting {
        return create(configManager.persistenceAdaptor.loadString(KEY))
    }

    companion object {
        const val KEY = "clientPIN"
    }
}