package com.webauthn4j.ctap.authenticator

import com.webauthn4j.converter.util.ObjectConverter
import com.webauthn4j.ctap.authenticator.store.*
import com.webauthn4j.ctap.core.util.internal.CipherUtil
import java.io.Serializable
import java.time.Instant
import javax.crypto.SecretKey

class UserCredentialBuilder(private val objectConverter: ObjectConverter, private val encryptionKey: SecretKey, private val encryptionIV: ByteArray) {

    private lateinit var credentialId: ByteArray
    private lateinit var credentialKey: CredentialKey
    private lateinit var userHandle: ByteArray
    private var username: String? = null
    private var displayName: String? = null
    private lateinit var rpId: String
    private var rpName: String? = null
    private var counter: Long = 0
    private lateinit var createdAt: Instant
    private var otherUI: Serializable? = null
    private val detailsBuilder: UserCredentialDetailsBuilder = UserCredentialDetailsBuilder()

    fun build(): UserCredential{
        val details = detailsBuilder.build()
        credentialKey.let {
            return if(it is ResidentCredentialKey){
                ResidentUserCredential(
                    credentialId,
                    it,
                    userHandle,
                    username,
                    displayName,
                    rpId,
                    rpName,
                    counter,
                    createdAt,
                    otherUI,
                    details
                )
            }
            else{
                // Let credentialId be the result of serializing and encrypting credentialSource
                // so that only this authenticator can decrypt it.
                val nonResidentUserCredentialEnvelope = NonResidentUserCredentialSource(
                    credentialKey as NonResidentCredentialKey,
                    userHandle,
                    username,
                    displayName,
                    rpId,
                    rpName,
                    createdAt,
                    otherUI,
                    details
                )
                val data = objectConverter.cborConverter.writeValueAsBytes(nonResidentUserCredentialEnvelope)
                val credentialId = CipherUtil.encryptWithAESCBCPKCS5Padding(
                    data,
                    encryptionKey,
                    encryptionIV
                )


                NonResidentUserCredential(
                    credentialId,
                    it as NonResidentCredentialKey,
                    userHandle,
                    username,
                    displayName,
                    rpId,
                    rpName,
                    createdAt,
                    otherUI,
                    details
                )
            }
        }
    }

    fun credentialId(value: ByteArray): UserCredentialBuilder {
        credentialId = value
        return this
    }

    fun userCredentialKey(value: CredentialKey): UserCredentialBuilder {
        credentialKey = value
        return this
    }

    fun userHandle(value: ByteArray): UserCredentialBuilder {
        userHandle = value
        return this
    }

    fun username(value: String?): UserCredentialBuilder {
        username = value
        return this
    }

    fun displayName(value: String?): UserCredentialBuilder {
        displayName = value
        return this
    }

    fun rpId(value: String): UserCredentialBuilder {
        rpId = value
        return this
    }

    fun rpName(value: String?): UserCredentialBuilder {
        rpName = value
        return this
    }

    fun counter(value: Long): UserCredentialBuilder {
        counter = value
        return this
    }

    fun createdAt(value: Instant): UserCredentialBuilder {
        createdAt = value
        return this
    }

    fun otherUI(value: Serializable?): UserCredentialBuilder {
        otherUI = value
        return this
    }

    fun details(): UserCredentialDetailsBuilder {
        return detailsBuilder
    }

    inner class UserCredentialDetailsBuilder{

        val map = HashMap<String, String>()

        fun entry(key: String, value: String){
            map[key] = value
        }

        fun build(): Map<String, String> {
            return map
        }

        fun and(): UserCredentialBuilder{
            return this@UserCredentialBuilder
        }
    }

}