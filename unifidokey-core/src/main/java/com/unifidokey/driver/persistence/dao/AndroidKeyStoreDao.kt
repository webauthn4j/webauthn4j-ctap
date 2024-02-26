package com.unifidokey.driver.persistence.dao

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import com.webauthn4j.data.SignatureAlgorithm
import com.webauthn4j.util.exception.UnexpectedCheckedException
import java.io.IOException
import java.security.InvalidAlgorithmParameterException
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.NoSuchAlgorithmException
import java.security.NoSuchProviderException
import java.security.cert.CertificateException
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.KeyGenerator

/**
 * [KeyStoreDao] for Android KeyStore
 */
class AndroidKeyStoreDao : KeyStoreDaoBase(createKeyStore(), "") {

    override fun createSecretKey(alias: String) {
        try {
            val keyGenerator =
                KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
            keyGenerator.init(
                KeyGenParameterSpec.Builder(
                    alias,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
                )
                    .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                    .setRandomizedEncryptionRequired(false)
                    .build()
            )
            keyGenerator.generateKey()
        } catch (e: NoSuchAlgorithmException) {
            throw UnexpectedCheckedException(e)
        } catch (e: NoSuchProviderException) {
            throw UnexpectedCheckedException(e)
        } catch (e: InvalidAlgorithmParameterException) {
            throw UnexpectedCheckedException(e)
        }
    }

    override fun createKeyPair(
        alias: String,
        algorithm: String,
        algorithmParameterSpec: AlgorithmParameterSpec?,
        signatureAlgorithm: SignatureAlgorithm,
        attestationChallenge: ByteArray?
    ) {
        try {
            val keyPairGenerator = KeyPairGenerator.getInstance(algorithm, "AndroidKeyStore")
            val builder = KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
            )
                .setDigests(signatureAlgorithm.messageDigestAlgorithm.jcaName)
                .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1) //TODO: support PSS alg
                .setIsStrongBoxBacked(true)
                .setAttestationChallenge(attestationChallenge)
            if (algorithmParameterSpec != null) {
                builder.setAlgorithmParameterSpec(algorithmParameterSpec)
            }
            keyPairGenerator.initialize(builder.build())
            keyPairGenerator.generateKeyPair()
        } catch (e: NoSuchAlgorithmException) {
            throw UnexpectedCheckedException(e)
        } catch (e: InvalidAlgorithmParameterException) {
            throw UnexpectedCheckedException(e)
        } catch (e: NoSuchProviderException) {
            throw UnexpectedCheckedException(e)
        }
    }

    companion object {
        private fun createKeyStore(): KeyStore {
            return try {
                val keyStore = KeyStore.getInstance("AndroidKeyStore")
                keyStore.load(null)
                keyStore
            } catch (e: KeyStoreException) {
                throw UnexpectedCheckedException(e)
            } catch (e: IOException) {
                throw UnexpectedCheckedException(e)
            } catch (e: CertificateException) {
                throw UnexpectedCheckedException(e)
            } catch (e: NoSuchAlgorithmException) {
                throw UnexpectedCheckedException(e)
            }
        }
    }
}