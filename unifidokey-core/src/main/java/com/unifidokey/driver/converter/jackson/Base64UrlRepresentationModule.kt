package com.unifidokey.driver.converter.jackson

import com.fasterxml.jackson.databind.module.SimpleModule
import com.webauthn4j.data.AuthenticatorAssertionResponse
import com.webauthn4j.data.AuthenticatorAttestationResponse
import com.webauthn4j.data.AuthenticatorResponse
import com.webauthn4j.data.PublicKeyCredential
import com.webauthn4j.data.PublicKeyCredentialDescriptor
import com.webauthn4j.data.PublicKeyCredentialUserEntity

class Base64UrlRepresentationModule : SimpleModule("Base64UrlRepresentationModule") {
    init {
        setMixInAnnotation(PublicKeyCredential::class.java, PublicKeyCredentialMixin::class.java)
        setMixInAnnotation(PublicKeyCredentialDescriptor::class.java, PublicKeyCredentialDescriptorMixin::class.java)
        setMixInAnnotation(PublicKeyCredentialUserEntity::class.java, PublicKeyCredentialUserEntityMixin::class.java)
        setMixInAnnotation(AuthenticatorResponse::class.java, AuthenticatorResponseMixin::class.java)
        setMixInAnnotation(AuthenticatorAttestationResponse::class.java, AuthenticatorAttestationResponseMixin::class.java)
        setMixInAnnotation(AuthenticatorAssertionResponse::class.java, AuthenticatorAssertionResponseMixin::class.java)
    }
}
