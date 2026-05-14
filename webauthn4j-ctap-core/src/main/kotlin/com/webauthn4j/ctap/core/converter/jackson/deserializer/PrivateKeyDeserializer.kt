package com.webauthn4j.ctap.core.converter.jackson.deserializer

import tools.jackson.core.JsonParser
import tools.jackson.databind.DeserializationContext
import tools.jackson.databind.deser.std.StdDeserializer
import tools.jackson.databind.node.BinaryNode
import tools.jackson.databind.node.ObjectNode
import com.webauthn4j.util.exception.NotImplementedException
import com.webauthn4j.util.exception.UnexpectedCheckedException
import java.security.KeyFactory
import java.security.NoSuchAlgorithmException
import java.security.PrivateKey
import java.security.spec.InvalidKeySpecException
import java.security.spec.PKCS8EncodedKeySpec

class PrivateKeyDeserializer : StdDeserializer<PrivateKey>(PrivateKey::class.java) {
    override fun deserialize(p: JsonParser, ctxt: DeserializationContext): PrivateKey {
        val node = p.readValueAsTree<ObjectNode>()
        val algorithm = node["algorithm"].stringValue()
        val format = node["format"].stringValue()
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
