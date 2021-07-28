package com.webauthn4j.ctap.authenticator.attestation

import com.webauthn4j.data.attestation.statement.AttestationStatement
import com.webauthn4j.data.attestation.statement.NoneAttestationStatement

class NoneAttestationStatementGenerator : AttestationStatementGenerator {

    override suspend fun generate(attestationStatementRequest: AttestationStatementRequest): AttestationStatement {
        return NoneAttestationStatement()
    }
}