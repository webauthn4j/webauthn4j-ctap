package com.unifidokey.driver.converter

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.dataformat.cbor.CBORFactory
import com.unifidokey.driver.converter.jackson.Base64UrlRepresentationModule
import com.webauthn4j.converter.util.ObjectConverter
import com.webauthn4j.data.PublicKeyCredentialCreationOptions
import org.junit.Test

class ConverterTest {

    @Test
    fun test(){
        val json = """
            {
              "attestation": "none",
              "authenticatorSelection": {
                "residentKey": "preferred",
                "userVerification": "preferred"
              },
              "challenge": "rZ4Fx3IrGrKuFKiDwzxFeYm7WZnhIAIKDZ1eOMxGoChFnepuTLqDDcRQMAQA7R5LPJDxm2AVP2QrhSTpMkSEuQ",
              "excludeCredentials": [
                {
                  "id": "PTQWQvL0xnIqf_V5GmgGUbjkPyXY7QvT7vYw9HNSErM",
                  "transports": [
                    "hybrid",
                    "internal"
                  ],
                  "type": "public-key"
                },
                {
                  "id": "q90cIq6_2IQ5X8J-S-5W8rGejH8_jb-QTjFsHQucROc",
                  "transports": [
                    "hybrid",
                    "internal"
                  ],
                  "type": "public-key"
                },
                {
                  "id": "_Qe-uGUWeCsb9q_sO_E2lF7dPan6GrjkA_1qDNcA934",
                  "transports": [
                    "hybrid",
                    "internal"
                  ],
                  "type": "public-key"
                }
              ],
              "extensions": {
                "credProps": true
              },
              "pubKeyCredParams": [
                {
                  "alg": -7,
                  "type": "public-key"
                },
                {
                  "alg": -257,
                  "type": "public-key"
                }
              ],
              "rp": {
                "id": "webauthn.io",
                "name": "webauthn.io"
              },
              "user": {
                "displayName": "test@sharplab.org",
                "id": "ZEdWemRFQnphR0Z5Y0d4aFlpNXZjbWM",
                "name": "test@sharplab.org"
              }
            }
        """.trimIndent()
        val jsonMapper = ObjectMapper()
        val cborMapper = ObjectMapper(CBORFactory())
        jsonMapper.registerModule(Base64UrlRepresentationModule())
        //jsonMapper.addMixIn(PublicKeyCredentialDescriptor::class.java, PublicKeyCredentialDescriptorMixin::class.java)
        val objectConverter = ObjectConverter(jsonMapper, cborMapper)
        val options = objectConverter.jsonConverter.readValue(json, PublicKeyCredentialCreationOptions::class.java)

    }

}