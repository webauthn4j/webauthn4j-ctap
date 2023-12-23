package com.unifidokey.app.handheld.presentation

import android.content.Context
import android.util.AttributeSet
import android.view.LayoutInflater
import android.widget.CompoundButton
import android.widget.TextView
import androidx.appcompat.widget.AppCompatImageView
import androidx.constraintlayout.widget.ConstraintLayout
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.checkbox.MaterialCheckBox
import com.unifidokey.R
import com.unifidokey.app.handheld.UnifidoKeyHandHeldApplication
import com.unifidokey.driver.persistence.entity.UserCredentialEntity

class RelyingPartyView(
    context: Context,
    attrs: AttributeSet
) : ConstraintLayout(context, attrs) {

    private val rpNameView: TextView
    private val rpIdView: TextView
    private val biometricAuthenticationCheckBox: MaterialCheckBox
    private val credentialListRecyclerView: RecyclerView
    private val deleteButtonView: AppCompatImageView
    private var credentialListRecyclerViewAdapter: CredentialListRecyclerViewAdapter = CredentialListRecyclerViewAdapter(this.context.applicationContext as UnifidoKeyHandHeldApplication)

    init {
        LayoutInflater.from(context).inflate(R.layout.relying_party_layout , this , true)
        rpNameView = this.findViewById(R.id.rpName_view)
        rpIdView = this.findViewById(R.id.rpId_view)
        biometricAuthenticationCheckBox= this.findViewById(R.id.bioAuth_checkbox)
        credentialListRecyclerView = this.findViewById(R.id.credential_list_view)
        deleteButtonView = this.findViewById(R.id.delete_menu_button)
    }

    override fun onAttachedToWindow() {
        super.onAttachedToWindow()
        credentialListRecyclerView.adapter = credentialListRecyclerViewAdapter
    }

    override fun onDetachedFromWindow() {
        credentialListRecyclerView.adapter = null
        super.onDetachedFromWindow()
    }

    var rpId: String? = rpIdView.text.toString()
        set(value) {
            rpIdView.text = value
            field = value
        }

    var rpName: String? = rpNameView.text.toString()
        set(value) {
            rpNameView.text = value
            field = value
        }

    var userCredentials: List<UserCredentialEntity> = emptyList()
        set(value){
            field = value
            credentialListRecyclerViewAdapter.submitList(value)
        }

    var biometricAuthentication: Boolean
        set(value) {
            biometricAuthenticationCheckBox.isChecked = value
        }
        get() {
            return biometricAuthenticationCheckBox.isChecked
        }

    var biometricAuthenticationEnabled: Boolean
        set(value) {
            biometricAuthenticationCheckBox.isEnabled = value
        }
        get() {
            return biometricAuthenticationCheckBox.isEnabled
        }

    fun setOnDeleteButtonClickListener(listener: OnClickListener?){
        deleteButtonView.setOnClickListener(listener)
    }

    fun hasOnDeleteButtonClickListeners(): Boolean{
        return deleteButtonView.hasOnClickListeners()
    }

    fun setOnBiometricAuthenticationCheckBoxCheckedChangeListener(listener: CompoundButton.OnCheckedChangeListener?){
        biometricAuthenticationCheckBox.setOnCheckedChangeListener(listener)
    }
}
