package com.unifidokey.app.handheld.presentation

import androidx.lifecycle.ViewModelProvider
import android.os.Bundle
import androidx.fragment.app.Fragment
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.databinding.DataBindingUtil
import androidx.recyclerview.widget.RecyclerView
import com.unifidokey.R
import com.unifidokey.app.handheld.UnifidoKeyHandHeldApplication
import com.unifidokey.databinding.CredentialsFragmentBinding

class CredentialsFragment : Fragment() {

    private lateinit var viewModel: CredentialsViewModel
    private val adapter : RelyingPartyListRecyclerViewAdapter by lazy{
        RelyingPartyListRecyclerViewAdapter(this.requireActivity().application as UnifidoKeyHandHeldApplication)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        viewModel = ViewModelProvider(this)[CredentialsViewModel::class.java]
    }

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        // Setup data binding
        val binding: CredentialsFragmentBinding = DataBindingUtil.inflate(inflater, R.layout.credentials_fragment, container, false)
        binding.viewModel = viewModel
        binding.lifecycleOwner = this

        val recyclerView = binding.root.findViewById<RecyclerView>(R.id.relying_party_list_recycler_view)
        recyclerView.adapter = adapter
        viewModel.relyingParties.observe(this.requireActivity()) { relyingParties ->
            adapter.submitList(relyingParties)
        }

        return binding.root
    }
}