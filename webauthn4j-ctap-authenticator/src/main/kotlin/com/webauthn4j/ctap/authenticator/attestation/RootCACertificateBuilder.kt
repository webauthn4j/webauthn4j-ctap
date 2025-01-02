package com.webauthn4j.ctap.authenticator.attestation

import com.webauthn4j.data.SignatureAlgorithm
import java.security.PrivateKey
import java.security.PublicKey

class RootCACertificateBuilder(
    subjectDN: String,
    publicKey: PublicKey,
    privateKey: PrivateKey,
    signatureAlgorithm: SignatureAlgorithm
) :
    CACertificateBuilder(subjectDN, publicKey, subjectDN, privateKey, signatureAlgorithm)
