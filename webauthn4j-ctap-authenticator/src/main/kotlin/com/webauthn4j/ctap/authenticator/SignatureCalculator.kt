package com.webauthn4j.ctap.authenticator

import com.webauthn4j.data.SignatureAlgorithm
import com.webauthn4j.util.SignatureUtil
import com.webauthn4j.util.exception.UnexpectedCheckedException
import java.security.InvalidKeyException
import java.security.PrivateKey
import java.security.Signature
import java.security.SignatureException

object SignatureCalculator {
    @JvmStatic
    fun calculate(
        alg: SignatureAlgorithm,
        privateKey: PrivateKey,
        signedData: ByteArray
    ): ByteArray {
        return try {
            val signature: Signature = SignatureUtil.createSignature(alg.jcaName)
            signature.initSign(privateKey)
            signature.update(signedData)
            signature.sign()
        } catch (e: SignatureException) {
            throw UnexpectedCheckedException(e)
        } catch (e: InvalidKeyException) {
            throw UnexpectedCheckedException(e)
        }
    }
}