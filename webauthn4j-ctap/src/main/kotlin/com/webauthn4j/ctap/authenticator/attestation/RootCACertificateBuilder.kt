package com.webauthn4j.ctap.authenticator.attestation

import java.security.PrivateKey
import java.security.PublicKey

class RootCACertificateBuilder(subjectDN: String, publicKey: PublicKey, privateKey: PrivateKey) :
    CACertificateBuilder(subjectDN, publicKey, subjectDN, privateKey)
