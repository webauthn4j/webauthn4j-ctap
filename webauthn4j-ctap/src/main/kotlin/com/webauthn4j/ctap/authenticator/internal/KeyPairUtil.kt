package com.webauthn4j.ctap.authenticator.internal

import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier
import com.webauthn4j.util.ECUtil
import com.webauthn4j.util.RSAUtil
import java.security.KeyPair

object KeyPairUtil {
    @JvmStatic
    fun createCredentialKeyPair(alg: COSEAlgorithmIdentifier): KeyPair {
        return when (alg) {
            COSEAlgorithmIdentifier.ES256 -> ECUtil.createKeyPair(null, ECUtil.P_256_SPEC)
            COSEAlgorithmIdentifier.ES384 -> ECUtil.createKeyPair(null, ECUtil.P_384_SPEC)
            COSEAlgorithmIdentifier.ES512 -> ECUtil.createKeyPair(null, ECUtil.P_521_SPEC)
            COSEAlgorithmIdentifier.RS1, COSEAlgorithmIdentifier.RS256, COSEAlgorithmIdentifier.RS384, COSEAlgorithmIdentifier.RS512 -> RSAUtil.createKeyPair() //TODO: revisit
            else -> throw IllegalArgumentException("algorithmIdentifier is not valid.")
        }
    }
}
