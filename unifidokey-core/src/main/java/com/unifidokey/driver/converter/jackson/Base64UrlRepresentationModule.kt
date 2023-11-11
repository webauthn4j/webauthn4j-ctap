package com.unifidokey.driver.converter.jackson

import com.fasterxml.jackson.databind.module.SimpleModule
import com.webauthn4j.data.PublicKeyCredentialDescriptor
import com.webauthn4j.data.PublicKeyCredentialUserEntity

class Base64UrlRepresentationModule : SimpleModule("Base64UrlRepresentationModule") {
    init {
        setMixInAnnotation(PublicKeyCredentialDescriptor::class.java, PublicKeyCredentialDescriptorMixin::class.java)
        setMixInAnnotation(PublicKeyCredentialUserEntity::class.java, PublicKeyCredentialUserEntityMixin::class.java)
    }
}
