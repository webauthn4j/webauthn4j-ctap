package com.unifidokey.app.handheld.presentation

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.LiveData
import androidx.lifecycle.map
import androidx.lifecycle.switchMap
import com.unifidokey.app.handheld.UnifidoKeyHandHeldApplication
import com.unifidokey.app.handheld.UnifidoKeyHandHeldComponent
import com.unifidokey.core.service.AuthenticatorService
import com.unifidokey.driver.persistence.dao.RelyingPartyDao
import com.unifidokey.driver.persistence.dto.RelyingPartyAndUserCredentialsDto

class CredentialsViewModel(application: Application) : AndroidViewModel(application) {

    private val unifidoKeyHandHeldApplication = application as UnifidoKeyHandHeldApplication
    private var unifidoKeyComponent: UnifidoKeyHandHeldComponent = unifidoKeyHandHeldApplication.unifidoKeyComponent
    private val relyingPartyDao: RelyingPartyDao = unifidoKeyComponent.relyingPartyDao

    val relyingParties: LiveData<List<RelyingPartyViewModel>> = relyingPartyDao.findAllLiveData().map { it.map { relyingPartyAndUserCredentialsDto -> RelyingPartyViewModel(unifidoKeyHandHeldApplication, relyingPartyAndUserCredentialsDto)  } }

}
