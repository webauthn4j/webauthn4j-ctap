package com.unifidokey.driver.persistence.converter.room

import androidx.room.TypeConverter
import com.webauthn4j.data.SignatureAlgorithm
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier

class SignatureAlgorithmConverter {
    @TypeConverter
    fun serialize(value: SignatureAlgorithm?): Long? {
        return if (value == null) null else COSEAlgorithmIdentifier.create(value).value
    }

    @TypeConverter
    fun deserialize(value: Long?): SignatureAlgorithm? {
        return if (value == null) null else COSEAlgorithmIdentifier.create(value)
            .toSignatureAlgorithm()
    }
}