/*
 * Copyright 2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.webauthn4j.ctap.authenticator.attestation

import com.webauthn4j.data.SignatureAlgorithm
import com.webauthn4j.data.attestation.authenticator.AAGUID
import com.webauthn4j.util.exception.UnexpectedCheckedException
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.DEROctetString
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

/**
 * Attestation certificate builder
 */
class AttestationCertificateBuilder internal constructor(
    private val subjectDN: String,
    private val publicKey: PublicKey,
    private val issuerDN: String,
    private val issuerPrivateKey: PrivateKey,
    private val signatureAlgorithm: SignatureAlgorithm
) {

    private var notBefore = Instant.parse("2000-01-01T00:00:00Z")
    private var notAfter = Instant.parse("2999-12-31T23:59:59Z")
    private var aaguid: AAGUID? = null

    fun notBefore(notBefore: Instant): AttestationCertificateBuilder {
        this.notBefore = notBefore
        return this
    }

    fun notAfter(notAfter: Instant): AttestationCertificateBuilder {
        this.notAfter = notAfter
        return this
    }

    fun aaguid(aaguid: AAGUID): AttestationCertificateBuilder {
        this.aaguid = aaguid
        return this
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
            aaguid.let {
                if (it != null) {
                    certificateBuilder.addExtension(
                        ID_FIDO_GEN_CE_AAGUID,
                        false,
                        DEROctetString(it.bytes)
                    )
                }
            }
            certificateBuilder.addExtension(
                Extension.basicConstraints,
                true,
                BasicConstraints(false)
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

    companion object {
        private val ID_FIDO_GEN_CE_AAGUID = ASN1ObjectIdentifier("1.3.6.1.4.1.45724.1.1.4").intern()
    }
}