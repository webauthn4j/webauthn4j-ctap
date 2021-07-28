package com.unifidokey.app.handheld.presentation

import android.app.Application
import android.view.View
import androidx.lifecycle.AndroidViewModel
import androidx.navigation.Navigation
import com.unifidokey.app.UnifidoKeyComponent
import com.unifidokey.app.handheld.UnifidoKeyHandHeldApplication
import com.unifidokey.driver.persistence.dao.UserCredentialDao
import com.unifidokey.driver.persistence.entity.UserCredentialEntity

class CredentialDetailsViewModel(application: Application) : AndroidViewModel(application) {
    private val userCredentialDao: UserCredentialDao
    lateinit var userCredentialEntity: UserCredentialEntity

    init {
        val unifidoKeyHandHeldApplication = application as UnifidoKeyHandHeldApplication
        val unifidoKeyComponent: UnifidoKeyComponent =
            unifidoKeyHandHeldApplication.unifidoKeyComponent
        userCredentialDao = unifidoKeyComponent.userCredentialDao
    }

    val username: String
        get() = userCredentialEntity.username
    val displayName: String
        get() = userCredentialEntity.displayName
    val createdAt: String
        get() = userCredentialEntity.createdAt.toString()
    val keyStorage: String
        get() = if (userCredentialEntity.keyAlias == null) "Database" else "KeyStore"

    fun onOkButtonClick(view: View) {
        Navigation.findNavController(view).popBackStack()
    }

    fun deleteUserCredential() {
        userCredentialDao.delete(userCredentialEntity.credentialId)
    }


}