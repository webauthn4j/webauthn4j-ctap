package com.unifidokey.app.handheld.presentation

import android.content.DialogInterface
import android.os.Bundle
import android.view.*
import android.widget.AdapterView
import android.widget.AdapterView.OnItemLongClickListener
import android.widget.ExpandableListView
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
import com.unifidokey.databinding.CredentialListFragmentBinding
import com.unifidokey.driver.persistence.dto.RelyingPartyAndUserCredentialsDto
import com.unifidokey.driver.persistence.entity.UserCredentialEntity
import org.slf4j.LoggerFactory

class CredentialListFragment : Fragment(), SearchView.OnQueryTextListener {

    private val logger = LoggerFactory.getLogger(CredentialListFragment::class.java)

    private lateinit var root: View
    private lateinit var viewModel: CredentialListViewModel
    private lateinit var adapter: CredentialListItemAdapter


    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {

        // Setup data binding
        viewModel = ViewModelProvider(this).get(CredentialListViewModel::class.java)
        val binding: CredentialListFragmentBinding =
            DataBindingUtil.inflate(inflater, R.layout.credential_list_fragment, container, false)
        root = binding.root
        binding.viewModel = viewModel
        viewModel.relyingParties.observe(viewLifecycleOwner) { relyingParties: List<RelyingPartyAndUserCredentialsDto> -> onRelyingPartiesChanged(relyingParties) }

        return binding.root
    }

    override fun onDestroyView() {
        super.onDestroyView()
        viewModel.relyingParties.removeObserver { relyingParties: List<RelyingPartyAndUserCredentialsDto> ->
            onRelyingPartiesChanged(
                relyingParties
            )
        }
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        // initialize views
        initializeCredentialListView()

        val menuHost: MenuHost = requireActivity()
        menuHost.addMenuProvider(object : MenuProvider {
            override fun onCreateMenu(menu: Menu, menuInflater: MenuInflater) {
                menuInflater.inflate(R.menu.credential_list, menu)
                val searchItem = menu.findItem(R.id.action_search)
                val searchView = searchItem.actionView as SearchView
                searchView.setOnQueryTextListener(this@CredentialListFragment)
            }

            override fun onMenuItemSelected(menuItem: MenuItem): Boolean {
                when (menuItem.itemId) {
                    R.id.action_search -> return true
                }
                return true
            }
        }, viewLifecycleOwner, Lifecycle.State.RESUMED)
    }

    //endregion
    //## User action event handlers ##

    override fun onQueryTextSubmit(query: String): Boolean {
        return false
    }

    override fun onQueryTextChange(newText: String): Boolean {
        adapter.filter.filter(newText)
        return true
    }

    private fun onRelyingPartiesChanged(relyingParties: List<RelyingPartyAndUserCredentialsDto>) {
        val credentialListView = root.findViewById<ExpandableListView>(R.id.credential_list_view)
        renewCredentialListAdapter(relyingParties, credentialListView)
        setRegistrationInstructionVisibility(relyingParties.isEmpty())
    }

    @Suppress("UNUSED_PARAMETER")
    private fun onItemLongClick(
        adapterView: AdapterView<*>,
        view: View,
        flatListPosition: Int,
        id: Long
    ): Boolean {
        val credentialListView = root.findViewById<ExpandableListView>(R.id.credential_list_view)
        val packed = credentialListView.getExpandableListPosition(flatListPosition)
        if (ExpandableListView.getPackedPositionType(packed) == ExpandableListView.PACKED_POSITION_TYPE_GROUP) {
            val index = ExpandableListView.getPackedPositionGroup(packed)
            val relyingPartyEntity = adapter.getGroup(index)
            AlertDialog.Builder(requireContext())
                .setTitle("UnifidoKey")
                .setMessage("Are you sure to delete the service \"" + relyingPartyEntity.name + "\"")
                .setPositiveButton("OK") { _: DialogInterface?, _: Int ->
                    viewModel.deleteRelyingParty(
                        relyingPartyEntity.id
                    )
                }
                .setNegativeButton("Cancel", null)
                .show()
        } else {
            val index = ExpandableListView.getPackedPositionGroup(packed)
            val childIndex = ExpandableListView.getPackedPositionChild(packed)
            val userCredentialEntity = adapter.getChild(index, childIndex)
            AlertDialog.Builder(requireContext())
                .setTitle("UnifidoKey")
                .setMessage("Are you sure to delete the user \"" + userCredentialEntity.displayName + "\"")
                .setPositiveButton("OK") { _: DialogInterface?, _: Int ->
                    viewModel.deleteUserCredential(
                        userCredentialEntity.credentialId
                    )
                }
                .setNegativeButton("Cancel", null)
                .show()
        }
        return true
    }

    @Suppress("UNUSED_PARAMETER")
    private fun onGroupClick(
        expandableListView: ExpandableListView,
        view: View,
        index: Int,
        childIndex: Long
    ): Boolean {
        return true
    }

    @Suppress("UNUSED_PARAMETER")
    private fun onChildClick(
        expandableListView: ExpandableListView,
        view: View,
        index: Int,
        childIndex: Int,
        id: Long
    ): Boolean {
        val userCredentialEntity = adapter.getChild(index, childIndex)
        navigateToCredentialDetailsFragment(view, userCredentialEntity)
        return true
    }

    private fun initializeCredentialListView() {
        val credentialListView = root.findViewById<ExpandableListView>(R.id.credential_list_view)
        credentialListView.setOnGroupClickListener { expandableListView: ExpandableListView, view: View, index: Int, childIndex: Long ->
            onGroupClick(
                expandableListView,
                view,
                index,
                childIndex
            )
        }
        credentialListView.setOnChildClickListener { expandableListView: ExpandableListView, view: View, index: Int, childIndex: Int, id: Long ->
            onChildClick(
                expandableListView,
                view,
                index,
                childIndex,
                id
            )
        }
        credentialListView.onItemLongClickListener =
            OnItemLongClickListener { adapterView: AdapterView<*>, view: View, flatListPosition: Int, id: Long ->
                onItemLongClick(
                    adapterView,
                    view,
                    flatListPosition,
                    id
                )
            }
        credentialListView.isTextFilterEnabled = true
    }

    private fun setRegistrationInstructionVisibility(visibility: Boolean) {
        val value = if (visibility) View.VISIBLE else View.INVISIBLE
        root.findViewById<View>(R.id.tapImageView).visibility = value
        root.findViewById<View>(R.id.registrationInstructionTextView).visibility = value
    }

    private fun renewCredentialListAdapter(
        relyingParties: List<RelyingPartyAndUserCredentialsDto>,
        credentialListView: ExpandableListView
    ) {
        adapter = CredentialListItemAdapter(requireContext(), relyingParties)
        credentialListView.setAdapter(adapter)
    }

    private fun navigateToCredentialDetailsFragment(
        view: View,
        userCredentialEntity: UserCredentialEntity?
    ) {
        val action =
            CredentialListFragmentDirections.actionCredentialListFragmentToCredentialDetailsFragment(
                userCredentialEntity!!
            )
        Navigation.findNavController(view).navigate(action)
    }


}