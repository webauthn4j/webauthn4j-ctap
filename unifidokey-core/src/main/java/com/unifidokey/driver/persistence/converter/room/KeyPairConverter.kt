package com.unifidokey.driver.persistence.converter.room

import androidx.room.TypeConverter
import com.webauthn4j.converter.util.CborConverter
import com.webauthn4j.converter.util.ObjectConverter
import com.webauthn4j.data.attestation.authenticator.COSEKey
import com.webauthn4j.data.attestation.authenticator.EC2COSEKey
import com.webauthn4j.data.attestation.authenticator.RSACOSEKey
import com.webauthn4j.util.Base64Util
import java.security.KeyPair
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey

class KeyPairConverter {
    private val cborConverter: CborConverter = ObjectConverter().cborConverter

    @TypeConverter
    fun serialize(value: KeyPair?): String? {
        if (value == null) {
            return null
        }
        val privateKey = value.private
        val publicKey = value.public
        return if (privateKey is RSAPublicKey && publicKey is RSAPublicKey) {
            val rsaCoseKey = RSACOSEKey.create(value)
            Base64Util.encodeToString(cborConverter.writeValueAsBytes(rsaCoseKey))
        } else if (privateKey is ECPrivateKey && publicKey is ECPublicKey) {
            val ec2CoseKey = EC2COSEKey.create(value)
            Base64Util.encodeToString(cborConverter.writeValueAsBytes(ec2CoseKey))
        } else {
            throw IllegalArgumentException("Provided key is not supported to be serialized.")
        }
    }

    @TypeConverter
    fun deserialize(value: String?): KeyPair? {
        if (value == null) {
            return null
        }
        val bytes = Base64Util.decode(value)
        val coseKey = cborConverter.readValue(bytes, COSEKey::class.java)
        return if (coseKey is RSACOSEKey || coseKey is EC2COSEKey) {
            val publicKey = coseKey.publicKey
            val privateKey = coseKey.privateKey
            KeyPair(publicKey, privateKey)
        } else {
            throw IllegalArgumentException("Provided key is not supported to be deserialized.")
        }
    }

}