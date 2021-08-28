package com.webauthn4j.ctap.authenticator.attestation

import com.webauthn4j.data.attestation.statement.NoneAttestationStatement

class NoneAttestationStatementGenerator : AttestationStatementGenerator {

    override suspend fun generate(attestationStatementRequest: AttestationStatementRequest): NoneAttestationStatement {
        return NoneAttestationStatement()
    }
}