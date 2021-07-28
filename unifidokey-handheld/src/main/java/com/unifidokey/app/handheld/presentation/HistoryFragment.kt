package com.unifidokey.app.handheld.presentation

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.databinding.DataBindingUtil
import androidx.fragment.app.Fragment
import androidx.lifecycle.ViewModelProvider
import androidx.recyclerview.widget.RecyclerView
import com.unifidokey.R
import com.unifidokey.databinding.HistoryFragmentBinding

/**
 * A fragment representing a list of Items.
 */
open class HistoryFragment : Fragment() {

    private lateinit var viewModel: HistoryViewModel
    private val adapter = HistoryItemRecyclerViewAdapter()


    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        viewModel = ViewModelProvider(this).get(HistoryViewModel::class.java)
    }

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        // Setup data binding
        val binding: HistoryFragmentBinding =
            DataBindingUtil.inflate(inflater, R.layout.history_fragment, container, false)
        binding.viewModel = viewModel
        binding.lifecycleOwner = this

        val recyclerView = binding.root.findViewById<RecyclerView>(R.id.history_recycler_view)
        recyclerView.adapter = adapter
        viewModel.events.observe(this.requireActivity(), { events -> adapter.submitList(events) })

        return binding.root
    }
}
