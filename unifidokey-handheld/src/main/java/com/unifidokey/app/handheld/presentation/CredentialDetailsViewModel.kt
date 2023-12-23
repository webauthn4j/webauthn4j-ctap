package com.unifidokey.app.handheld.presentation

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.LiveData
import androidx.lifecycle.map
import com.unifidokey.app.UnifidoKeyComponent
import com.unifidokey.app.handheld.UnifidoKeyHandHeldApplication
import com.unifidokey.core.config.ConfigManager
import com.unifidokey.driver.persistence.dao.UserCredentialDao
import com.unifidokey.driver.persistence.entity.UserCredentialEntity

class CredentialDetailsViewModel(application: Application) : AndroidViewModel(application) {
    private val userCredentialDao: UserCredentialDao
    private val configManager: ConfigManager
    lateinit var userCredentialEntity: UserCredentialEntity

    init {
        val unifidoKeyHandHeldApplication = application as UnifidoKeyHandHeldApplication
        val unifidoKeyComponent: UnifidoKeyComponent = unifidoKeyHandHeldApplication.unifidoKeyComponent
        userCredentialDao = unifidoKeyComponent.userCredentialDao
        configManager = unifidoKeyComponent.configManager
    }

    val username: String?
        get() = userCredentialEntity.username
    val displayName: String?
        get() = userCredentialEntity.displayName
    val createdAt: String
        get() = userCredentialEntity.createdAt.toString()
    val credentialStorage: String
        get() = if (userCredentialEntity.keyAlias == null) "Database" else "KeyStore"

    fun deleteUserCredential() {
        userCredentialDao.delete(userCredentialEntity.credentialId)
    }


}