package com.webauthn4j.ctap.authenticator.attestation

import com.webauthn4j.util.ArrayUtil
import java.security.KeyPair

class FIDOU2FAttestationStatementRequest {
    @Suppress("JoinDeclarationAndAssignment")
    val credentialKey: KeyPair
    val keyHandle: ByteArray
        get() = ArrayUtil.clone(field)
    val applicationParameter: ByteArray
        get() = ArrayUtil.clone(field)
    val challengeParameter: ByteArray
        get() = ArrayUtil.clone(field)

    constructor(
        credentialKey: KeyPair,
        keyHandle: ByteArray,
        applicationParameter: ByteArray,
        challengeParameter: ByteArray
    ) {
        this.credentialKey = credentialKey
        this.keyHandle = ArrayUtil.clone(keyHandle)
        this.applicationParameter = ArrayUtil.clone(applicationParameter)
        this.challengeParameter = ArrayUtil.clone(challengeParameter)
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is FIDOU2FAttestationStatementRequest) return false

        if (credentialKey != other.credentialKey) return false
        if (!keyHandle.contentEquals(other.keyHandle)) return false
        if (!applicationParameter.contentEquals(other.applicationParameter)) return false
        if (!challengeParameter.contentEquals(other.challengeParameter)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = credentialKey.hashCode()
        result = 31 * result + keyHandle.contentHashCode()
        result = 31 * result + applicationParameter.contentHashCode()
        result = 31 * result + challengeParameter.contentHashCode()
        return result
    }


}