package com.unifidokey.app.handheld.presentation

import android.content.DialogInterface
import android.view.View
import androidx.annotation.UiThread
import androidx.appcompat.app.AlertDialog
import androidx.navigation.Navigation
import com.unifidokey.app.handheld.UnifidoKeyHandHeldApplication
import com.unifidokey.app.handheld.UnifidoKeyHandHeldComponent
import com.unifidokey.driver.persistence.dao.UserCredentialDao
import com.unifidokey.driver.persistence.entity.UserCredentialEntity

class UserCredentialViewModel(val unifidoKeyHandHeldApplication: UnifidoKeyHandHeldApplication, private val userCredentialEntity: UserCredentialEntity) {

    private var unifidoKeyComponent: UnifidoKeyHandHeldComponent = unifidoKeyHandHeldApplication.unifidoKeyComponent
    private val userCredentialDao: UserCredentialDao = unifidoKeyComponent.userCredentialDao

    val username: String?
        get() = userCredentialEntity.username

    val displayName: String?
        get() = userCredentialEntity.displayName

    @UiThread
    fun onClick(view: View) {
        navigateToCredentialDetailsFragment(view, userCredentialEntity)
    }

    @UiThread
    fun onLongClick(view: View): Boolean{
    AlertDialog.Builder(view.context)
    .setTitle("UnifidoKey")
    .setMessage("Are you sure to delete the user \"" + userCredentialEntity.displayName + "\"")
    .setPositiveButton("OK") { _: DialogInterface?, _: Int ->
        deleteUserCredential(
            userCredentialEntity.credentialId
        )
    }
    .setNegativeButton("Cancel", null)
    .show()
        return true
    }

    private fun navigateToCredentialDetailsFragment(
        view: View,
        userCredentialEntity: UserCredentialEntity?
    ) {
        val action =
            CredentialsFragmentDirections.actionCredentialListFragmentToCredentialDetailsFragment(
                userCredentialEntity!!
            )
        Navigation.findNavController(view).navigate(action)
    }

    private fun deleteUserCredential(credentialId: ByteArray) {
        userCredentialDao.delete(credentialId)
    }
}