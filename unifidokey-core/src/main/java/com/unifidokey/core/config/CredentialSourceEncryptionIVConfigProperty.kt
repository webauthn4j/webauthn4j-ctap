package com.unifidokey.core.config

class CredentialSourceEncryptionIVConfigProperty internal constructor(configManager: ConfigManager) :
    ConfigPropertyBase<ByteArray>(configManager, KEY, ConfigManager.generateIV(), true, false, false) {

    override fun save(value: ByteArray) {
        configManager.persistenceAdaptor.saveBytes(KEY, value)
    }

    @Throws(ConfigNotFoundException::class)
    override fun load(): ByteArray {
        return configManager.persistenceAdaptor.loadBytes(KEY)!!
    }

    companion object {
        const val KEY = "credentialSourceEncryptionIV"
    }
}
