package com.unifidokey.app.handheld.presentation

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.LiveData
import com.unifidokey.app.UnifidoKeyComponent
import com.unifidokey.app.handheld.UnifidoKeyHandHeldApplication
import com.unifidokey.driver.persistence.dao.RelyingPartyDao
import com.unifidokey.driver.persistence.dao.UserCredentialDao
import com.unifidokey.driver.persistence.dto.RelyingPartyAndUserCredentialsDto
import org.slf4j.LoggerFactory

class CredentialListViewModel(application: Application) : AndroidViewModel(application) {
    private val logger = LoggerFactory.getLogger(CredentialListViewModel::class.java)
    private val unifidoKeyComponent: UnifidoKeyComponent
    private val relyingPartyDao: RelyingPartyDao
    private val userCredentialDao: UserCredentialDao
    val relyingParties: LiveData<List<RelyingPartyAndUserCredentialsDto>>
        get() = relyingPartyDao.findAllLiveData()

    init {
        val unifidoKeyHandHeldApplication = application as UnifidoKeyHandHeldApplication
        unifidoKeyComponent = unifidoKeyHandHeldApplication.unifidoKeyComponent
        relyingPartyDao = unifidoKeyComponent.relyingPartyDao
        userCredentialDao = unifidoKeyComponent.userCredentialDao
    }

    fun deleteRelyingParty(rpId: String) {
        relyingPartyDao.delete(rpId)
    }

    fun deleteUserCredential(credentialId: ByteArray?) {
        userCredentialDao.delete(credentialId)
    }

    fun startBLEPairing(): Boolean {
        return try {
            unifidoKeyComponent.bleService.startPairing()
            true
        } catch (e: RuntimeException) {
            logger.error("Unexpected exception is thrown", e)
            false
        }
    }

    fun stopBLEPairing() {
        try {
            unifidoKeyComponent.bleService.stopPairing()
        } catch (e: RuntimeException) {
            logger.error("Unexpected exception is thrown", e)
        }
    }

}