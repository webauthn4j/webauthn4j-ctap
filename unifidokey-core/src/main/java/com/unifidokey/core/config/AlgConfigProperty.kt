package com.unifidokey.core.config

import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier

class AlgConfigProperty internal constructor(configManager: ConfigManager) :
    ConfigPropertyBase<Set<COSEAlgorithmIdentifier>>(
        configManager,
        KEY,
        setOf(COSEAlgorithmIdentifier.ES256),
        ReleaseLevel.GA,
        true,
        true
    ) {

    override fun save(value: Set<COSEAlgorithmIdentifier>) {
        configManager.persistenceAdaptor.saveStringSet(
            KEY,
            value.map { it.value.toString() }.toSet()
        )
    }

    @Throws(ConfigNotFoundException::class)
    override fun load(): Set<COSEAlgorithmIdentifier> {
        return configManager.persistenceAdaptor.loadStringSet(KEY)
            .map { COSEAlgorithmIdentifier.create(it.toLong()) }.toSet()
    }

    companion object {
        const val KEY = "alg"
    }
}