package com.unifidokey.core.config

import com.webauthn4j.ctap.authenticator.data.settings.AttachmentSetting
import com.webauthn4j.ctap.authenticator.data.settings.AttachmentSetting.Companion.create

class PlatformConfigProperty internal constructor(configManager: ConfigManager) :
    ConfigPropertyBase<AttachmentSetting>(configManager, KEY, AttachmentSetting.CROSS_PLATFORM, false, true, true) {

    override fun save(value: AttachmentSetting) {
        configManager.persistenceAdaptor.saveString(KEY, value.value)
    }

    @Throws(ConfigNotFoundException::class)
    override fun load(): AttachmentSetting {
        return create(configManager.persistenceAdaptor.loadString(KEY))
    }

    companion object {
        const val KEY = "platform"
    }
}
