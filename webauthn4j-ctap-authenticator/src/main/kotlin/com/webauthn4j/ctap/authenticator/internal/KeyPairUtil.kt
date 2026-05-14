package com.webauthn4j.ctap.authenticator.internal

import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier
import com.webauthn4j.util.ECUtil
import com.webauthn4j.util.RSAUtil
import java.security.KeyPair
import java.security.KeyPairGenerator

object KeyPairUtil {
    @JvmStatic
    fun createCredentialKeyPair(alg: COSEAlgorithmIdentifier): KeyPair {
        return when (alg) {
            COSEAlgorithmIdentifier.ES256 -> ECUtil.createKeyPair(null, ECUtil.P_256_SPEC)
            COSEAlgorithmIdentifier.ES384 -> ECUtil.createKeyPair(null, ECUtil.P_384_SPEC)
            COSEAlgorithmIdentifier.ES512 -> ECUtil.createKeyPair(null, ECUtil.P_521_SPEC)
            COSEAlgorithmIdentifier.RS1, COSEAlgorithmIdentifier.RS256, COSEAlgorithmIdentifier.RS384, COSEAlgorithmIdentifier.RS512 -> RSAUtil.createKeyPair()
            COSEAlgorithmIdentifier.ML_DSA_44, COSEAlgorithmIdentifier.ML_DSA_65, COSEAlgorithmIdentifier.ML_DSA_87 ->
                KeyPairGenerator.getInstance(alg.toSignatureAlgorithm().jcaName).generateKeyPair()
            else -> throw IllegalArgumentException("algorithmIdentifier is not valid.")
        }
    }
}
