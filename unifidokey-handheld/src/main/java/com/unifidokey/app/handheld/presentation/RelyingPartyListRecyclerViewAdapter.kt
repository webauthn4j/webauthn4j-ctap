package com.unifidokey.app.handheld.presentation

import android.view.LayoutInflater
import android.view.ViewGroup
import androidx.databinding.DataBindingUtil
import androidx.fragment.app.findFragment
import androidx.lifecycle.LifecycleOwner
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.unifidokey.R
import com.unifidokey.app.handheld.UnifidoKeyHandHeldApplication
import com.unifidokey.databinding.RelyingPartyContainerLayoutBinding

class RelyingPartyListRecyclerViewAdapter(val unifidoKeyHandHeldApplication: UnifidoKeyHandHeldApplication) : ListAdapter<RelyingPartyViewModel, RelyingPartyListRecyclerViewAdapter.ViewHolder>(DIFF_CALLBACK) {

    companion object {
        val DIFF_CALLBACK: DiffUtil.ItemCallback<RelyingPartyViewModel> = object : DiffUtil.ItemCallback<RelyingPartyViewModel>() {
            override fun areItemsTheSame(oldItem: RelyingPartyViewModel, newItem: RelyingPartyViewModel): Boolean {
                return oldItem.relyingParty === newItem.relyingParty
            }

            override fun areContentsTheSame(oldItem: RelyingPartyViewModel, newItem: RelyingPartyViewModel): Boolean {
                return oldItem.relyingParty == newItem.relyingParty
            }

        }
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val binding: RelyingPartyContainerLayoutBinding = DataBindingUtil.inflate(
            LayoutInflater.from(parent.context),
            R.layout.relying_party_container_layout,
            parent,
            false
        )
        binding.lifecycleOwner = parent.findFragment()
        return ViewHolder(binding)
    }

    override fun onBindViewHolder(viewHolder: ViewHolder, position: Int) {
        val relyingPartyViewModel = getItem(position)!!

        viewHolder.binding.viewModel = relyingPartyViewModel
        viewHolder.binding.relyingPartyView.userCredentials = relyingPartyViewModel.relyingParty.userCredentialEntities
    }

    inner class ViewHolder(val binding: RelyingPartyContainerLayoutBinding) : RecyclerView.ViewHolder(binding.root)

}