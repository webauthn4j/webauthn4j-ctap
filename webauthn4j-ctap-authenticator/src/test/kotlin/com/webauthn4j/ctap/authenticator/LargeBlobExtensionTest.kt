package com.webauthn4j.ctap.authenticator

import com.webauthn4j.ctap.authenticator.extension.LargeBlobExtensionProcessor
import com.webauthn4j.ctap.core.data.*
import com.webauthn4j.data.*
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier
import com.webauthn4j.data.extension.authenticator.*
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.*

class LargeBlobExtensionTest {
    @Test
    fun roundTripUsesUnsignedOutputsAndIsolatesCredentials() = runBlocking {
        val authenticator=CtapAuthenticator(extensionProcessors=listOf(LargeBlobExtensionProcessor()))
        val session=authenticator.createSession()
        val converter=authenticator.objectConverter
        fun registrationExtensions()=converter.cborMapper.readValue(converter.cborMapper.writeValueAsBytes(mapOf("largeBlob" to mapOf("support" to "preferred"))),AuthenticationExtensionsAuthenticatorInputs::class.java) as AuthenticationExtensionsAuthenticatorInputs<RegistrationExtensionAuthenticatorInput>
        fun authenticationExtensions(value:Map<String,Any>)=converter.cborMapper.readValue(converter.cborMapper.writeValueAsBytes(mapOf("largeBlob" to value)),AuthenticationExtensionsAuthenticatorInputs::class.java) as AuthenticationExtensionsAuthenticatorInputs<AuthenticationExtensionAuthenticatorInput>
        suspend fun create(id:Byte):PublicKeyCredentialDescriptor {
            val response=session.makeCredential(AuthenticatorMakeCredentialRequest(ByteArray(32),CtapPublicKeyCredentialRpEntity("example.com","Example"),CtapPublicKeyCredentialUserEntity(byteArrayOf(id),"User","User"),listOf(PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY,COSEAlgorithmIdentifier.ES256)),emptyList(),registrationExtensions(),AuthenticatorMakeCredentialRequest.Options(rk=true,uv=true),null,null))
            assertEquals(CtapStatusCode.CTAP2_OK,response.statusCode)
            val data=response.responseData!!
            assertEquals(true,(data.unsignedExtensionOutputs!!["largeBlob"] as Map<*,*>)["supported"])
            assertFalse(data.authenticatorData.extensions?.keys?.contains("largeBlob") ?: false)
            val wire=converter.cborMapper.readTree(converter.cborMapper.writeValueAsBytes(data))
            assertTrue(wire.has("6"))
            return PublicKeyCredentialDescriptor(PublicKeyCredentialType.PUBLIC_KEY,data.authenticatorData.attestedCredentialData!!.credentialId,null)
        }
        val first=create(1);val second=create(2)
        suspend fun assertBlob(credential:PublicKeyCredentialDescriptor?,input:Map<String,Any>):AuthenticatorGetAssertionResponseData {
            val response=session.getAssertion(AuthenticatorGetAssertionRequest("example.com",ByteArray(32),credential?.let{listOf(it)},authenticationExtensions(input),AuthenticatorGetAssertionRequest.Options(up=true,uv=true),null,null))
            assertEquals(CtapStatusCode.CTAP2_OK,response.statusCode)
            val data=response.responseData!!
            assertEquals(0,data.authData[32].toInt() and 0x80)
            assertTrue(converter.cborMapper.readTree(converter.cborMapper.writeValueAsBytes(data)).has("8") || data.unsignedExtensionOutputs==null)
            return data
        }
        val bytes=byteArrayOf(1,2,3,4)
        assertEquals(true,(assertBlob(first,mapOf("write" to bytes,"originalSize" to 12)).unsignedExtensionOutputs!!["largeBlob"] as Map<*,*>)["written"])
        assertNull(assertBlob(second,mapOf("read" to true)).unsignedExtensionOutputs)
        val recovered=assertBlob(first,mapOf("read" to true)).unsignedExtensionOutputs!!["largeBlob"] as Map<*,*>
        assertArrayEquals(bytes,recovered["blob"] as ByteArray)
        assertEquals(12L,recovered["originalSize"])
        val rejected=assertBlob(null,mapOf("write" to bytes,"originalSize" to 12)).unsignedExtensionOutputs!!["largeBlob"] as Map<*,*>
        assertEquals(false,rejected["written"])
    }
}
