package com.webauthn4j.ctap.authenticator.attestation

import com.webauthn4j.data.attestation.statement.AttestationStatement

/**
 * Generates attestation statement
 */
interface AttestationStatementGenerator {
    suspend fun generate(attestationStatementRequest: AttestationStatementRequest): AttestationStatement
}
