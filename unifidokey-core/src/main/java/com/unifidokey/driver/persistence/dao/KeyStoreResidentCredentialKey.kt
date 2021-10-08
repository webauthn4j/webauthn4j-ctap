package com.unifidokey.driver.persistence.dao

import com.webauthn4j.ctap.authenticator.data.credential.ResidentCredentialKey
import com.webauthn4j.data.SignatureAlgorithm
import com.webauthn4j.data.attestation.statement.AttestationCertificatePath
import java.security.KeyPair
import java.security.KeyStore

/**
 * Specialized [ResidentCredentialKey] for [KeyStore]
 */
class KeyStoreResidentCredentialKey(
    alg: SignatureAlgorithm,
    val keyAlias: String,
    keyPair: KeyPair,
    val credentialAttestationCertificatePath: AttestationCertificatePath
) : ResidentCredentialKey(alg, keyPair)
