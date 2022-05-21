package com.webauthn4j.ctap.authenticator.data.credential

import com.webauthn4j.data.SignatureAlgorithm
import java.security.KeyPair

/**
 * Core interface representing user credential key (pair)
 */
interface CredentialKey {
    val alg: SignatureAlgorithm?

    /**
     * Return user credential key pair
     *
     * @return user credential key pair
     */
    val keyPair: KeyPair?
}