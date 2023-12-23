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
import androidx.appcompat.widget.SearchView
import androidx.core.view.MenuHost
import androidx.core.view.MenuProvider
import androidx.databinding.DataBindingUtil
import androidx.fragment.app.Fragment
import androidx.lifecycle.Lifecycle
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

        // Setup data binding
        viewModel = ViewModelProvider(this)[CredentialDetailsViewModel::class.java]
        val binding: CredentialDetailsFragmentBinding = DataBindingUtil.inflate(
            inflater,
            R.layout.credential_details_fragment,
            container,
            false
        )
        viewModel.userCredentialEntity = CredentialDetailsFragmentArgs.fromBundle(requireArguments()).userCredential
        binding.viewModel = viewModel
        binding.lifecycleOwner = this
        root = binding.root
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        val menuHost: MenuHost = requireActivity()
        menuHost.addMenuProvider(object : MenuProvider {
            override fun onCreateMenu(menu: Menu, menuInflater: MenuInflater) {
                menuInflater.inflate(R.menu.credential_details, menu)
            }

            override fun onMenuItemSelected(menuItem: MenuItem): Boolean {
                // Handle action bar item clicks here. The action bar will
                // automatically handle clicks on the Home/Up button, so long
                // as you specify a parent activity in AndroidManifest.xml.
                when (menuItem.itemId) {
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
        }, viewLifecycleOwner, Lifecycle.State.RESUMED)
    }

    //endregion
    //region ## user action event handlers

    //endregion
}