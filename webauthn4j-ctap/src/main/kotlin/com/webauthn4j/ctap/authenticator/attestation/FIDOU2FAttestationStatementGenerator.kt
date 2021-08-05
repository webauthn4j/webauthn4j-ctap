package com.webauthn4j.ctap.authenticator.attestation

import com.webauthn4j.ctap.authenticator.SignatureCalculator.calculate
import com.webauthn4j.data.attestation.authenticator.EC2COSEKey
import com.webauthn4j.data.attestation.statement.AttestationCertificatePath
import com.webauthn4j.data.attestation.statement.AttestationStatement
import com.webauthn4j.data.attestation.statement.FIDOU2FAttestationStatement
import java.nio.ByteBuffer
import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey

class FIDOU2FAttestationStatementGenerator(
    private val attestationPrivateKey: PrivateKey,
    attestationCertificate: X509Certificate
) : AttestationStatementGenerator {

    private val attestationCertificatePath: AttestationCertificatePath =
        AttestationCertificatePath(attestationCertificate, emptyList())

    override suspend fun generate(attestationStatementRequest: AttestationStatementRequest): AttestationStatement {
        val publicKey = attestationStatementRequest.userCredentialKey.keyPair!!.public
        if(publicKey !is ECPublicKey){
            throw IllegalArgumentException("attestationStatementRequest.userCredentialKey.keyPair must be Elliptic Curve key pair.")
        }
        val credentialPublicKey =
            EC2COSEKey.create(publicKey)
        val clientDataHash = attestationStatementRequest.clientDataHash
        val signedData = getSignedData(
            attestationStatementRequest.rpIdHash,
            attestationStatementRequest.credentialId,
            credentialPublicKey,
            clientDataHash
        )
        val sig = calculate(
            attestationStatementRequest.algorithmIdentifier.toSignatureAlgorithm(),
            attestationPrivateKey,
            signedData
        )
        return FIDOU2FAttestationStatement(attestationCertificatePath, sig)
    }

    private fun getSignedData(
        rpIdHash: ByteArray,
        credentialId: ByteArray,
        credentialPublicKey: EC2COSEKey,
        clientDataHash: ByteArray
    ): ByteArray {
        val rfu: Byte = 0x00
        val userPublicKey = getPublicKeyBytes(credentialPublicKey)
        return ByteBuffer.allocate(1 + rpIdHash.size + clientDataHash.size + credentialId.size + userPublicKey.size)
            .put(rfu).put(rpIdHash).put(clientDataHash).put(credentialId).put(userPublicKey).array()
    }

    private fun getPublicKeyBytes(ec2CoseKey: EC2COSEKey): ByteArray {
        val x = ec2CoseKey.x
        val y = ec2CoseKey.y
        val format: Byte = 4
        return ByteBuffer.allocate(1 + x.size + y.size).put(format).put(x).put(y).array()
    }

}