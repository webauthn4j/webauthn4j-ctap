package com.webauthn4j.ctap.core.converter.jackson.deserializer

import com.fasterxml.jackson.core.JsonParser
import com.fasterxml.jackson.databind.DeserializationContext
import com.fasterxml.jackson.databind.deser.std.StdDeserializer
import com.fasterxml.jackson.databind.node.BinaryNode
import com.fasterxml.jackson.databind.node.ObjectNode
import com.webauthn4j.util.exception.NotImplementedException
import com.webauthn4j.util.exception.UnexpectedCheckedException
import java.io.IOException
import java.security.KeyFactory
import java.security.NoSuchAlgorithmException
import java.security.PublicKey
import java.security.spec.InvalidKeySpecException
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

class PublicKeyDeserializer : StdDeserializer<PublicKey>(PublicKey::class.java) {
    @Throws(IOException::class)
    override fun deserialize(p: JsonParser, ctxt: DeserializationContext): PublicKey {
        val oc = p.codec
        val node = oc.readTree<ObjectNode>(p)
        val algorithm = node["algorithm"].asText()
        val format = node["format"].asText()
        val encoded = (node["encoded"] as BinaryNode).binaryValue()
        return when (format) {
            "PKCS#8" -> when (algorithm) {
                "EC" -> createECPublicKeyFromPKCS8(encoded)
                else -> throw NotImplementedException()
            }
            "X.509" -> when (algorithm) {
                "EC" -> createECPublicKeyFromX509(encoded)
                else -> throw NotImplementedException()
            }
            else -> throw NotImplementedException()
        }
    }

    private fun createECPublicKeyFromPKCS8(encoded: ByteArray): PublicKey {
        return try {
            val keySpec = PKCS8EncodedKeySpec(encoded)
            val keyFactory = KeyFactory.getInstance("EC")
            keyFactory.generatePublic(keySpec)
        } catch (e: NoSuchAlgorithmException) {
            throw UnexpectedCheckedException(e)
        } catch (e: InvalidKeySpecException) {
            throw UnexpectedCheckedException(e)
        }
    }

    private fun createECPublicKeyFromX509(encoded: ByteArray): PublicKey {
        return try {
            val keySpec = X509EncodedKeySpec(encoded)
            val keyFactory = KeyFactory.getInstance("EC")
            keyFactory.generatePublic(keySpec)
        } catch (e: NoSuchAlgorithmException) {
            throw UnexpectedCheckedException(e)
        } catch (e: InvalidKeySpecException) {
            throw UnexpectedCheckedException(e)
        }
    }
}