package com.unifidokey.driver.attestation

import android.content.Context
import com.google.android.gms.safetynet.SafetyNet
import com.webauthn4j.converter.AuthenticatorDataConverter
import com.webauthn4j.converter.util.ObjectConverter
import com.webauthn4j.ctap.authenticator.attestation.AttestationStatementProvider
import com.webauthn4j.ctap.authenticator.attestation.AttestationStatementRequest
import com.webauthn4j.data.attestation.statement.AndroidSafetyNetAttestationStatement
import com.webauthn4j.data.attestation.statement.Response
import com.webauthn4j.data.jws.JWSFactory
import com.webauthn4j.util.MessageDigestUtil
import java.nio.ByteBuffer
import kotlin.coroutines.Continuation
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlin.coroutines.suspendCoroutine

class AndroidSafetyNetAttestationStatementProvider : AttestationStatementProvider {

    @Suppress("JoinDeclarationAndAssignment")
    private val apiKey: String
    private val context: Context
    private val jwsFactory: JWSFactory
    private val authenticatorDataConverter: AuthenticatorDataConverter

    @Suppress("ConvertSecondaryConstructorToPrimary")
    constructor(apiKey: String, context: Context, objectConverter: ObjectConverter) {
        this.apiKey = apiKey
        this.context = context
        jwsFactory = JWSFactory(objectConverter)
        authenticatorDataConverter = AuthenticatorDataConverter(objectConverter)
    }


    override suspend fun provide(attestationStatementRequest: AttestationStatementRequest): AndroidSafetyNetAttestationStatement {
        val ver = "12685023"
        val authenticatorData =
            authenticatorDataConverter.convert(attestationStatementRequest.authenticatorData)
        val clientDataHash = attestationStatementRequest.clientDataHash
        val nonce = MessageDigestUtil.createSHA256().digest(
            ByteBuffer.allocate(authenticatorData.size + clientDataHash.size).put(authenticatorData)
                .put(clientDataHash).array()
        )
        val jws = getAttestationResponseJWS(context, nonce)
        val responseJWS = jwsFactory.parse(jws, Response::class.java)
        return AndroidSafetyNetAttestationStatement(ver, responseJWS)
    }

    private suspend fun getAttestationResponseJWS(context: Context, nonce: ByteArray) =
        suspendCoroutine { continuation: Continuation<String> ->
            SafetyNet.getClient(context).attest(nonce, apiKey)
                .addOnSuccessListener { continuation.resume(it.jwsResult!!) }
            SafetyNet.getClient(context).attest(nonce, apiKey)
                .addOnFailureListener { continuation.resumeWithException(it) }
        }

}