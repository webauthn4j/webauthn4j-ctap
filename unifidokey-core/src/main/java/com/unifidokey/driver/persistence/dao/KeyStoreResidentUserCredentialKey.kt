package com.unifidokey.driver.persistence.dao

import com.webauthn4j.ctap.authenticator.store.ResidentUserCredentialKey
import com.webauthn4j.data.SignatureAlgorithm
import com.webauthn4j.data.attestation.statement.AttestationCertificatePath
import java.security.KeyPair
import java.security.KeyStore

/**
 * Specialized [ResidentUserCredentialKey] for [KeyStore]
 */
class KeyStoreResidentUserCredentialKey(
    alg: SignatureAlgorithm,
    val keyAlias: String,
    keyPair: KeyPair,
    val credentialAttestationCertificatePath: AttestationCertificatePath
) : ResidentUserCredentialKey(alg, keyPair)
