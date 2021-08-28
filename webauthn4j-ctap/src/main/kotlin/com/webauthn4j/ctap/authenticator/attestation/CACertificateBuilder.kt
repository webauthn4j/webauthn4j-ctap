package com.webauthn4j.ctap.authenticator.attestation

import com.webauthn4j.data.SignatureAlgorithm
import com.webauthn4j.util.exception.UnexpectedCheckedException
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.cert.CertIOException
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.OperatorCreationException
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.math.BigInteger
import java.security.PrivateKey
import java.security.PublicKey
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import java.time.Instant
import java.util.*
import javax.security.auth.x500.X500Principal

open class CACertificateBuilder internal constructor(
    private val subjectDN: String,
    private val publicKey: PublicKey,
    private val issuerDN: String,
    private val issuerPrivateKey: PrivateKey,
    private val signatureAlgorithm: SignatureAlgorithm
) {

    private var notBefore = Instant.parse("2000-01-01T00:00:00Z")
    private var notAfter = Instant.parse("2999-12-31T23:59:59Z")

    fun notBefore(notBefore: Instant) {
        this.notBefore = notBefore
    }

    fun notAfter(notAfter: Instant) {
        this.notAfter = notAfter
    }

    fun build(): X509Certificate {
        return try {
            val certificateBuilder: X509v3CertificateBuilder = JcaX509v3CertificateBuilder(
                X500Principal(issuerDN),
                BigInteger.valueOf(1),
                Date.from(notBefore),
                Date.from(notAfter),
                X500Principal(subjectDN),
                publicKey
            )
            certificateBuilder.addExtension(
                Extension.basicConstraints,
                false,
                BasicConstraints(true)
            )
            val contentSigner =
                JcaContentSignerBuilder(signatureAlgorithm.jcaName).build(issuerPrivateKey)
            val certificateHolder = certificateBuilder.build(contentSigner)
            JcaX509CertificateConverter().getCertificate(certificateHolder)
        } catch (e: CertificateException) {
            throw UnexpectedCheckedException(e)
        } catch (e: OperatorCreationException) {
            throw UnexpectedCheckedException(e)
        } catch (e: CertIOException) {
            throw UnexpectedCheckedException(e)
        }
    }
}