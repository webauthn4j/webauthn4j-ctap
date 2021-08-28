package com.webauthn4j.ctap.authenticator.attestation

import com.webauthn4j.data.SignatureAlgorithm
import com.webauthn4j.util.exception.UnexpectedCheckedException
import java.security.KeyFactory
import java.security.NoSuchAlgorithmException
import java.security.PrivateKey
import java.security.PublicKey
import java.security.cert.X509Certificate
import java.security.spec.InvalidKeySpecException
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

@Suppress("MemberVisibilityCanBePrivate")
object DemoAttestationConstants {

    const val DEMO_ROOT_CA_NAME = "CN=UnifidoKeyDemoRootCA,O=WebAuthn4J Project,C=US"
    const val DEMO_INTERMEDIATE_CA_NAME =
        "CN=UnifidoKeyDemoIntermediateCA,O=WebAuthn4J Project,C=US"
    const val DEMO_ATTESTATION_NAME =
        "CN=UnifidoKeyDemoAttestation,O=WebAuthn4J Project,OU=Authenticator Attestation,C=US"

    /**
     * Demo Root CA Certificate. Signed with hard coded private key, DO NOT USE for production use-case
     */
    val DEMO_ROOT_CA_CERTIFICATE: X509Certificate

    /**
     * Demo Intermediate CA Certificate. Signed with hard coded private key, DO NOT USE for production use-case
     */
    val DEMO_INTERMEDIATE_CA_CERTIFICATE: X509Certificate

    val DEMO_ROOT_CA_PUBLIC_KEY =
        loadPublicKeyFromClassPath("/attestation/3tier/public/3tier-test-root-CA.der")
    val DEMO_ROOT_CA_PRIVATE_KEY =
        loadPrivateKeyFromClassPath("/attestation/3tier/private/3tier-test-root-CA.der")
    val DEMO_INTERMEDIATE_CA_PUBLIC_KEY =
        loadPublicKeyFromClassPath("/attestation/3tier/public/3tier-test-intermediate-CA.der")
    val DEMO_INTERMEDIATE_CA_PRIVATE_KEY =
        loadPrivateKeyFromClassPath("/attestation/3tier/private/3tier-test-intermediate-CA.der")
    val DEMO_ATTESTATION_PUBLIC_KEY =
        loadPublicKeyFromClassPath("/attestation/3tier/public/3tier-test-authenticator.der")
    val DEMO_ATTESTATION_PRIVATE_KEY =
        loadPrivateKeyFromClassPath("/attestation/3tier/private/3tier-test-authenticator.der")

    init {
        DEMO_ROOT_CA_CERTIFICATE = RootCACertificateBuilder(
            DEMO_ROOT_CA_NAME,
            DEMO_ROOT_CA_PUBLIC_KEY,
            DEMO_ROOT_CA_PRIVATE_KEY,
            SignatureAlgorithm.ES256
        ).build()
        DEMO_INTERMEDIATE_CA_CERTIFICATE = CACertificateBuilder(
            DEMO_INTERMEDIATE_CA_NAME,
            DEMO_INTERMEDIATE_CA_PUBLIC_KEY,
            DEMO_ROOT_CA_NAME,
            DEMO_ROOT_CA_PRIVATE_KEY,
            SignatureAlgorithm.ES256
        ).build()
    }

    private fun loadPublicKeyFromClassPath(classpath: String): PublicKey {
        val data = ResourceLoader().load(classpath)
        return loadPublicKey(data)
    }

    private fun loadPrivateKeyFromClassPath(classpath: String): PrivateKey {
        val data = ResourceLoader().load(classpath)
        return loadPrivateKey(data)
    }

    private fun loadPublicKey(bytes: ByteArray?): PublicKey {
        val keySpec = X509EncodedKeySpec(bytes)
        val keyFactory: KeyFactory
        return try {
            keyFactory = KeyFactory.getInstance("EC")
            keyFactory.generatePublic(keySpec)
        } catch (e: NoSuchAlgorithmException) {
            throw UnexpectedCheckedException(e)
        } catch (e: InvalidKeySpecException) {
            throw UnexpectedCheckedException(e)
        }
    }

    private fun loadPrivateKey(bytes: ByteArray?): PrivateKey {
        val keySpec = PKCS8EncodedKeySpec(bytes)
        val keyFactory: KeyFactory
        return try {
            keyFactory = KeyFactory.getInstance("EC")
            keyFactory.generatePrivate(keySpec)
        } catch (e: NoSuchAlgorithmException) {
            throw UnexpectedCheckedException(e)
        } catch (e: InvalidKeySpecException) {
            throw UnexpectedCheckedException(e)
        }
    }


}