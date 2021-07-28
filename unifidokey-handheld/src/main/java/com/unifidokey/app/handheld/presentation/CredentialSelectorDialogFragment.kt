package com.unifidokey.app.handheld.presentation

import android.content.Intent
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.AdapterView
import android.widget.AdapterView.OnItemClickListener
import android.widget.ListView
import androidx.databinding.DataBindingUtil
import androidx.fragment.app.Fragment
import androidx.lifecycle.ViewModelProvider
import androidx.localbroadcastmanager.content.LocalBroadcastManager
import com.unifidokey.R
import com.unifidokey.databinding.CredentialChooserDialogFragmentBinding

class CredentialSelectorDialogFragment : Fragment(),
    CredentialSelectorDialogViewModel.EventHandlers {
    private lateinit var viewModel: CredentialSelectorDialogViewModel

    //region## Lifecycle event handlers ##
    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        val binding: CredentialChooserDialogFragmentBinding = DataBindingUtil.inflate(
            inflater,
            R.layout.credential_chooser_dialog_fragment,
            container,
            false
        )
        viewModel = ViewModelProvider(this).get(CredentialSelectorDialogViewModel::class.java)
        binding.viewModel = viewModel
        binding.handlers = viewModel
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        val intent = requireActivity().intent
        val request =
            intent.getSerializableExtra(CredentialSelectorDialogActivity.EXTRA_REQUEST) as CredentialSelectorDialogActivityRequest
        viewModel.credentials = request.credentials
        initializeCredentialListView()
    }

    //endregion

    private fun initializeCredentialListView() {
        val credentialListView = requireActivity().findViewById<ListView>(R.id.credential_list_view)
        val adapter = CredentialSelectorDialogAdapter(requireContext(), viewModel.credentials)
        credentialListView.adapter = adapter
        credentialListView.onItemClickListener =
            OnItemClickListener { parent: AdapterView<*>, view: View, position: Int, id: Long ->
                onItemClick(
                    parent,
                    view,
                    position,
                    id
                )
            }
    }

    @Suppress("UNUSED_PARAMETER")
    private fun onItemClick(parent: AdapterView<*>, view: View, position: Int, id: Long) {
        val credentialViewModel = viewModel.credentials[position]
        sendResponseIntent(credentialViewModel)
        requireActivity().finish()
    }

    private fun sendResponseIntent(credentialViewModel: CredentialViewModel) {
        val intent = Intent()
        val response = CredentialSelectorDialogActivityResponse(credentialViewModel)
        intent.putExtra(CredentialSelectorDialogActivity.EXTRA_RESPONSE, response)
        intent.action = CredentialSelectorDialogActivity.ACTION_OPEN
        val localBroadcastManager = LocalBroadcastManager.getInstance(requireContext())
        localBroadcastManager.sendBroadcast(intent)
    }

    companion object {
        fun newInstance(): CredentialSelectorDialogFragment {
            return CredentialSelectorDialogFragment()
        }
    }
}