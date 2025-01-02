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
import java.security.PrivateKey
import java.security.spec.InvalidKeySpecException
import java.security.spec.PKCS8EncodedKeySpec

class PrivateKeyDeserializer : StdDeserializer<PrivateKey>(PrivateKey::class.java) {
    @Throws(IOException::class)
    override fun deserialize(p: JsonParser, ctxt: DeserializationContext): PrivateKey {
        val oc = p.codec
        val node = oc.readTree<ObjectNode>(p)
        val algorithm = node["algorithm"].asText()
        val format = node["format"].asText()
        val encoded = (node["encoded"] as BinaryNode).binaryValue()
        return when (format) {
            "PKCS#8" -> when (algorithm) {
                "EC" -> createECPrivateKey(encoded)
                else -> throw NotImplementedException()
            }
            else -> throw NotImplementedException()
        }
    }

    private fun createECPrivateKey(encoded: ByteArray): PrivateKey {
        return try {
            val keySpec = PKCS8EncodedKeySpec(encoded)
            val keyFactory = KeyFactory.getInstance("EC")
            keyFactory.generatePrivate(keySpec)
        } catch (e: NoSuchAlgorithmException) {
            throw UnexpectedCheckedException(e)
        } catch (e: InvalidKeySpecException) {
            throw UnexpectedCheckedException(e)
        }
    }
}