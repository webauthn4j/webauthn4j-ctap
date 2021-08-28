package com.unifidokey.core.adapter

import com.unifidokey.core.setting.KeyStorageSetting
import com.webauthn4j.ctap.authenticator.store.InMemoryAuthenticatorPropertyStore
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier

class InMemoryUnifidoKeyAuthenticatorPropertyStore(
    override var algorithms: Set<COSEAlgorithmIdentifier>,
    override var keyStorageSetting: KeyStorageSetting
) : InMemoryAuthenticatorPropertyStore(), UnifidoKeyAuthenticatorPropertyStore
