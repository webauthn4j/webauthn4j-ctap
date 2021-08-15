package com.webauthn4j.ctap.authenticator.store

import com.webauthn4j.data.SignatureAlgorithm
import java.security.KeyPair

open class ResidentCredentialKey(
    override val alg: SignatureAlgorithm,
    override val keyPair: KeyPair
) : CredentialKey
