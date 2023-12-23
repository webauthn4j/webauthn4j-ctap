package com.unifidokey.app.handheld.presentation

import android.view.LayoutInflater
import android.view.ViewGroup
import androidx.databinding.DataBindingUtil
import androidx.fragment.app.findFragment
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.unifidokey.R
import com.unifidokey.app.handheld.UnifidoKeyHandHeldApplication
import com.unifidokey.databinding.CredentialListItemLayoutBinding
import com.unifidokey.driver.persistence.entity.UserCredentialEntity

class CredentialListRecyclerViewAdapter(private val unifidoKeyHandHeldApplication: UnifidoKeyHandHeldApplication) : ListAdapter<UserCredentialEntity, CredentialListRecyclerViewAdapter.ViewHolder>(DIFF_CALLBACK) {

    companion object {
        val DIFF_CALLBACK: DiffUtil.ItemCallback<UserCredentialEntity> = object : DiffUtil.ItemCallback<UserCredentialEntity>() {
            override fun areItemsTheSame(oldItem: UserCredentialEntity, newItem: UserCredentialEntity): Boolean {
                return oldItem === newItem
            }

            override fun areContentsTheSame(oldItem: UserCredentialEntity, newItem: UserCredentialEntity): Boolean {
                return oldItem == newItem
            }

        }
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val binding: CredentialListItemLayoutBinding = DataBindingUtil.inflate(
            LayoutInflater.from(parent.context),
            R.layout.credential_list_item_layout,
            parent,
            false
        )
        binding.lifecycleOwner = parent.findFragment()
        return ViewHolder(binding)
    }

    override fun onBindViewHolder(viewHolder: ViewHolder, position: Int) {
        val userCredentialEntity = getItem(position)!!
        viewHolder.binding.viewModel = UserCredentialViewModel(unifidoKeyHandHeldApplication, userCredentialEntity)
    }

    inner class ViewHolder(val binding: CredentialListItemLayoutBinding) :
        RecyclerView.ViewHolder(binding.root)

}