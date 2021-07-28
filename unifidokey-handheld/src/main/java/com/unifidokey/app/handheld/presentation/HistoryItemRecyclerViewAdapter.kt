package com.unifidokey.app.handheld.presentation

import android.view.LayoutInflater
import android.view.ViewGroup
import androidx.databinding.DataBindingUtil
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.unifidokey.R
import com.unifidokey.databinding.HistoryItemLayoutBinding
import com.webauthn4j.ctap.authenticator.event.Event

class HistoryItemRecyclerViewAdapter :
    ListAdapter<Event, HistoryItemRecyclerViewAdapter.ViewHolder>(DIFF_CALLBACK) {

    companion object {
        val DIFF_CALLBACK: DiffUtil.ItemCallback<Event> = object : DiffUtil.ItemCallback<Event>() {
            override fun areItemsTheSame(oldItem: Event, newItem: Event): Boolean {
                return oldItem === newItem
            }

            override fun areContentsTheSame(oldItem: Event, newItem: Event): Boolean {
                return oldItem == newItem
            }

        }
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val binding: HistoryItemLayoutBinding = DataBindingUtil.inflate(
            LayoutInflater.from(parent.context),
            R.layout.history_item_layout,
            parent,
            false
        )
        return ViewHolder(binding)
    }

    override fun onBindViewHolder(viewHolder: ViewHolder, position: Int) {
        val event = getItem(position)!!
        viewHolder.binding.viewModel = HistoryItemViewModel(event)
    }

    inner class ViewHolder(val binding: HistoryItemLayoutBinding) :
        RecyclerView.ViewHolder(binding.root)

}