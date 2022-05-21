package com.webauthn4j.ctap.authenticator.attestation

import com.webauthn4j.data.attestation.statement.NoneAttestationStatement

class NoneAttestationStatementProvider : AttestationStatementProvider {

    override suspend fun provide(attestationStatementRequest: AttestationStatementRequest): NoneAttestationStatement {
        return NoneAttestationStatement()
    }
}