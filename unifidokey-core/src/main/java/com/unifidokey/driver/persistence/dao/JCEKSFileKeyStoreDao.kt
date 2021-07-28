package com.unifidokey.driver.persistence.dao

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import com.webauthn4j.ctap.authenticator.attestation.RootCACertificateBuilder
import com.webauthn4j.util.exception.UnexpectedCheckedException
import java.io.FileInputStream
import java.io.IOException
import java.security.*
import java.security.cert.Certificate
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

class JCEKSFileKeyStoreDao : KeyStoreDaoBase {

    @JvmOverloads
    constructor(filename: String? = null, password: String? = "") : super(
        createKeyStore(
            filename,
            password
        ), password
    )

    private val secureRandom: SecureRandom = SecureRandom()

    override fun createSecretKey(alias: String) {
        val key = ByteArray(16)
        secureRandom.nextBytes(key)
        val secretKey: SecretKey = SecretKeySpec(key, "AES")
        val entry = KeyStore.SecretKeyEntry(secretKey)
        val protectionParameter: KeyStore.ProtectionParameter =
            KeyStore.PasswordProtection(password!!.toCharArray())
        try {
            keyStore.setEntry(alias, entry, protectionParameter)
        } catch (e: KeyStoreException) {
            throw UnexpectedCheckedException(e)
        }
    }

    override fun createKeyPair(
        alias: String,
        algorithm: String,
        algorithmParameterSpec: AlgorithmParameterSpec?,
        digest: String,
        attestationChallenge: ByteArray?
    ) {
        try {
            val keyPairGenerator = KeyPairGenerator.getInstance(algorithm)
            val builder = KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
            )
                .setDigests(digest)
                .setAttestationChallenge(attestationChallenge)
            if (algorithmParameterSpec != null) {
                builder.setAlgorithmParameterSpec(algorithmParameterSpec)
            }
            keyPairGenerator.initialize(builder.build())
            val keyPair = keyPairGenerator.generateKeyPair()
            val certificates = arrayOfNulls<Certificate>(1)
            certificates[0] = generateSelfSignedCertificate(keyPair)
            keyStore.setKeyEntry(alias, keyPair.private, password!!.toCharArray(), certificates)
        } catch (e: NoSuchAlgorithmException) {
            throw UnexpectedCheckedException(e)
        } catch (e: InvalidAlgorithmParameterException) {
            throw UnexpectedCheckedException(e)
        } catch (e: KeyStoreException) {
            throw UnexpectedCheckedException(e)
        }
    }

    private fun generateSelfSignedCertificate(keyPair: KeyPair): X509Certificate {
        val rootCACertificateBuilder = RootCACertificateBuilder(
            "CN=UnifidoKeyKeystoreKey,O=WebAuthn4J Project,C=US",
            keyPair.public,
            keyPair.private
        )
        //TODO: add attestationChallenge extension
        return rootCACertificateBuilder.build()
    }

    companion object {
        private fun createKeyStore(filename: String?, password: String?): KeyStore {
            return try {
                val keyStore = KeyStore.getInstance("JCEKS")
                if (filename == null) {
                    keyStore.load(null, password?.toCharArray())
                } else {
                    FileInputStream(filename).use { stream ->
                        keyStore.load(
                            stream,
                            password!!.toCharArray()
                        )
                    }
                }
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