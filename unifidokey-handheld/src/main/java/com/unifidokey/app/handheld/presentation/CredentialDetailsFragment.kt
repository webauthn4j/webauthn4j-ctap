package com.unifidokey.app.handheld.presentation

import android.content.DialogInterface
import android.os.Bundle
import android.view.LayoutInflater
import android.view.Menu
import android.view.MenuInflater
import android.view.MenuItem
import android.view.View
import android.view.ViewGroup
import androidx.appcompat.app.AlertDialog
import androidx.databinding.DataBindingUtil
import androidx.fragment.app.Fragment
import androidx.lifecycle.ViewModelProvider
import androidx.navigation.Navigation
import com.unifidokey.R
import com.unifidokey.databinding.CredentialDetailsFragmentBinding
import org.slf4j.LoggerFactory

class CredentialDetailsFragment : Fragment() {
    private val logger = LoggerFactory.getLogger(CredentialDetailsFragment::class.java)
    private lateinit var root: View
    private lateinit var viewModel: CredentialDetailsViewModel

    //region## Lifecycle event handlers ##
    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        initializeToolbar()

        // Setup data binding
        viewModel = ViewModelProvider(this).get(CredentialDetailsViewModel::class.java)
        val binding: CredentialDetailsFragmentBinding = DataBindingUtil.inflate(
            inflater,
            R.layout.credential_details_fragment,
            container,
            false
        )
        root = binding.root
        binding.viewModel = viewModel
        val userCredentialEntity =
            CredentialDetailsFragmentArgs.fromBundle(requireArguments()).userCredential
        viewModel.userCredentialEntity = userCredentialEntity
        return binding.root
    }

    //endregion
    //region ## user action event handlers
    override fun onCreateOptionsMenu(menu: Menu, inflater: MenuInflater) {
        super.onCreateOptionsMenu(menu, inflater)

        // Inflate the menu; this adds items to the action bar if it is present.
        inflater.inflate(R.menu.credential_details, menu)
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        when (item.itemId) {
            R.id.action_delete -> {
                return try {
                    AlertDialog.Builder(requireActivity())
                        .setTitle("UnifidoKey")
                        .setMessage("Are you sure to delete the user \"" + viewModel.displayName + "\"")
                        .setPositiveButton("OK") { _: DialogInterface?, _: Int ->
                            viewModel.deleteUserCredential()
                            Navigation.findNavController(root).popBackStack()
                        }
                        .setNegativeButton("Cancel", null)
                        .show()
                    true
                } catch (e: RuntimeException) {
                    logger.error("Unexpected exception is thrown", e)
                    false
                }
            }
            else -> throw IllegalStateException()
        }
    }

    //endregion
    private fun initializeToolbar() {
        setHasOptionsMenu(true)
    }
}