package com.unifidokey.driver.attestation

import com.google.common.truth.Truth
import com.unifidokey.driver.persistence.dao.AndroidKeyStoreDao
import com.unifidokey.driver.persistence.dao.KeyStoreDao
import com.webauthn4j.data.SignatureAlgorithm
import org.junit.Test
import java.util.*

class AndroidKeyAttestationStatementGeneratorTest {

    private val keyStoreDao: KeyStoreDao = AndroidKeyStoreDao()

    @Test
    fun certificate_test() {
        val alias = UUID.randomUUID().toString()
        keyStoreDao.createCredentialKeyPair(alias, SignatureAlgorithm.ES256, ByteArray(32))
        val attestationCertificatePath = keyStoreDao.findCredentialAttestationCertificatePath(alias)
        Truth.assertThat(attestationCertificatePath!!.endEntityAttestationCertificate.certificate.issuerDN)
            .isNotEqualTo("fake")
    }
}