package com.unifidokey.app.handheld.presentation

import android.content.DialogInterface
import android.view.View
import android.widget.CompoundButton
import androidx.appcompat.app.AlertDialog
import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.map
import com.unifidokey.app.handheld.UnifidoKeyHandHeldApplication
import com.unifidokey.app.handheld.UnifidoKeyHandHeldComponent
import com.unifidokey.core.setting.BiometricAuthenticationSetting
import com.unifidokey.driver.persistence.dao.RelyingPartyDao
import com.unifidokey.driver.persistence.dto.RelyingPartyAndUserCredentialsDto
import com.unifidokey.driver.persistence.entity.RelyingPartyEntity

class RelyingPartyViewModel(unifidoKeyHandHeldApplication: UnifidoKeyHandHeldApplication, val relyingParty: RelyingPartyAndUserCredentialsDto) {

    private val unifidoKeyComponent: UnifidoKeyHandHeldComponent = unifidoKeyHandHeldApplication.unifidoKeyComponent
    private val configManager = unifidoKeyComponent.configManager
    private val relyingPartyDao: RelyingPartyDao = unifidoKeyComponent.relyingPartyDao

    val biometricAuthentication: MutableLiveData<Boolean> by lazy {
        val liveData = MutableLiveData(relyingParty.relyingPartyEntity.biometricAuthentication)
        liveData.observeForever{
            if(liveData.value != it){
                updateRelyingParty(it)
            }
        }
        return@lazy liveData
    }

    val rpId: String = relyingParty.relyingPartyEntity.id
    val rpName: String = relyingParty.relyingPartyEntity.name ?: relyingParty.relyingPartyEntity.id

    val biometricAuthenticationGlobalState: LiveData<Boolean> = configManager.biometricAuthentication.liveData.map {it.value }.apply { observeForever{} }
    fun onDeleteButtonClick(view: View){
        confirmAndDeleteRelyingParty(view)
    }

    fun onLongClick(view: View): Boolean{
        return confirmAndDeleteRelyingParty(view)
    }

    fun biometricAuthenticationCheckBoxCheckedChange(buttonView: CompoundButton, isChecked: Boolean){
        if(isChecked != biometricAuthentication.value){
            updateRelyingParty(isChecked)
        }
    }

    private fun confirmAndDeleteRelyingParty(view: View): Boolean{
        val relyingPartyEntity = relyingParty.relyingPartyEntity
        AlertDialog.Builder(view.context)
            .setTitle("UnifidoKey")
            .setMessage("Are you sure to delete the service \"" + relyingPartyEntity.name + "\"")
            .setPositiveButton("OK") { _: DialogInterface?, _: Int ->
                deleteRelyingParty(
                    relyingPartyEntity.id
                )
            }
            .setNegativeButton("Cancel", null)
            .show()
        return true
    }

    private fun updateRelyingParty(biometricAuthentication: Boolean) {
        val dto = relyingPartyDao.findOne(relyingParty.relyingPartyEntity.id) ?: TODO()
        val entity = dto.relyingPartyEntity
        val newEntity = RelyingPartyEntity(
            entity.sid,
            entity.id,
            entity.name,
            entity.icon,
            biometricAuthentication
        )
        relyingPartyDao.update(newEntity)
    }

    private fun deleteRelyingParty(rpId: String) : Boolean{
        relyingPartyDao.delete(rpId)
        return true
    }


}