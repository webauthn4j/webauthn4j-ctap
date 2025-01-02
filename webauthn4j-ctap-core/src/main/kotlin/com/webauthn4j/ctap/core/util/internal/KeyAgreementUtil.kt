package com.webauthn4j.ctap.core.util.internal

import com.webauthn4j.util.exception.UnexpectedCheckedException
import java.security.InvalidKeyException
import java.security.NoSuchAlgorithmException
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import javax.crypto.KeyAgreement

object KeyAgreementUtil {
    fun generateSecret(localPrivateKey: ECPrivateKey?, remotePublicKey: ECPublicKey?): ByteArray {
        return try {
            val keyAgreement = KeyAgreement.getInstance("ECDH")
            keyAgreement.init(localPrivateKey)
            keyAgreement.doPhase(remotePublicKey, true)
            keyAgreement.generateSecret()
        } catch (e: NoSuchAlgorithmException) {
            throw UnexpectedCheckedException(e)
        } catch (e: InvalidKeyException) {
            throw UnexpectedCheckedException(e)
        }
    }
}
