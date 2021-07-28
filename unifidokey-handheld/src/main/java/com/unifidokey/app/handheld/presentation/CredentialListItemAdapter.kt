package com.unifidokey.app.handheld.presentation

import android.content.Context
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.*
import com.unifidokey.R
import com.unifidokey.driver.persistence.dto.RelyingPartyAndUserCredentialsDto
import com.unifidokey.driver.persistence.entity.RelyingPartyEntity
import com.unifidokey.driver.persistence.entity.UserCredentialEntity
import java.util.*
import java.util.stream.Collectors

class CredentialListItemAdapter internal constructor(
    context: Context,
    private val originalRelyingParties: List<RelyingPartyAndUserCredentialsDto>
) : BaseExpandableListAdapter(), Filterable {
    private val layoutInflater: LayoutInflater
    private val filter: Filter = CredentialListFilter()
    private var filteredRelyingParties: List<RelyingPartyAndUserCredentialsDto>

    init {
        filteredRelyingParties = originalRelyingParties
        layoutInflater = context.getSystemService(Context.LAYOUT_INFLATER_SERVICE) as LayoutInflater
    }

    override fun getGroupCount(): Int {
        return filteredRelyingParties.size
    }

    override fun getChildrenCount(index: Int): Int {
        return filteredRelyingParties[index].userCredentialEntities.size
    }

    override fun getGroup(index: Int): RelyingPartyEntity {
        return filteredRelyingParties[index].relyingPartyEntity
    }

    override fun getChild(index: Int, childIndex: Int): UserCredentialEntity {
        return filteredRelyingParties[index].userCredentialEntities[childIndex]
    }

    override fun getGroupId(index: Int): Long {
        return index.toLong()
    }

    override fun getChildId(index: Int, childIndex: Int): Long {
        return childIndex.toLong()
    }

    override fun hasStableIds(): Boolean {
        return true
    }

    override fun getGroupView(
        index: Int,
        isExpanded: Boolean,
        view: View?,
        parent: ViewGroup?
    ): View {
        val groupView = layoutInflater.inflate(R.layout.credential_list_rp_layout, parent, false)
        val expandableListView = parent as ExpandableListView
        val rpNameView = groupView.findViewById<TextView>(R.id.rpName_view)
        rpNameView.text = getGroup(index).name
        val rpIdView = groupView.findViewById<TextView>(R.id.rpId_view)
        rpIdView.text = getGroup(index).id
        expandableListView.expandGroup(index)
        return groupView
    }

    override fun getChildView(
        index: Int,
        childIndex: Int,
        isExpanded: Boolean,
        view: View?,
        parent: ViewGroup?
    ): View {
        val childView =
            layoutInflater.inflate(R.layout.credential_list_credential_layout, parent, false)
        val displayNameView = childView.findViewById<TextView>(R.id.displayName_view)
        displayNameView.text = getChild(index, childIndex).displayName
        val usernameView = childView.findViewById<TextView>(R.id.username_view)
        usernameView.text = getChild(index, childIndex).username
        return childView
    }

    override fun isChildSelectable(index: Int, childIndex: Int): Boolean {
        return true
    }

    override fun getFilter(): Filter {
        return filter
    }

    inner class CredentialListFilter : Filter() {
        override fun performFiltering(constraint: CharSequence): FilterResults {
            val result = FilterResults()
            if (constraint.toString().isNotEmpty()) {
                val query = constraint.toString()
                val filtered = originalRelyingParties
                    .filter { set: RelyingPartyAndUserCredentialsDto? ->
                        matchQuery(
                            query,
                            set!!.relyingPartyEntity
                        ) || set.userCredentialEntities.stream()
                            .anyMatch { userCredentialEntity: UserCredentialEntity ->
                                matchQuery(
                                    query,
                                    userCredentialEntity
                                )
                            }
                    }
                    .map { set: RelyingPartyAndUserCredentialsDto? ->
                        val userCredentials: List<UserCredentialEntity> =
                            if (matchQuery(query, set!!.relyingPartyEntity)) {
                                set.userCredentialEntities
                            } else {
                                set.userCredentialEntities.stream()
                                    .filter { userCredentialEntity: UserCredentialEntity ->
                                        matchQuery(
                                            query,
                                            userCredentialEntity
                                        )
                                    }.collect(Collectors.toList())
                            }
                        RelyingPartyAndUserCredentialsDto(set.relyingPartyEntity, userCredentials)
                    }
                result.count = filtered.size
                result.values = filtered
            } else {
                result.count = originalRelyingParties.size
                result.values = originalRelyingParties
            }
            return result
        }

        override fun publishResults(constraint: CharSequence, results: FilterResults) {
            @Suppress("UNCHECKED_CAST")
            filteredRelyingParties = results.values as List<RelyingPartyAndUserCredentialsDto>
            notifyDataSetChanged()
        }

        private fun matchQuery(query: String, userCredentialEntity: UserCredentialEntity): Boolean {
            return match(query, userCredentialEntity.username) || match(
                query,
                userCredentialEntity.displayName
            )
        }

        private fun matchQuery(query: String, relyingPartyEntity: RelyingPartyEntity): Boolean {
            return match(query, relyingPartyEntity.id) || match(query, relyingPartyEntity.name)
        }

        private fun match(query: String?, targetText: String?): Boolean {
            if (query == null || targetText == null) {
                return false
            }
            val keywords = query.split("\\s+".toRegex()).toTypedArray()
                .map { obj: String -> obj.trim { it <= ' ' } }
            for (keyword in keywords) {
                if (targetText.lowercase(Locale.getDefault())
                        .contains(keyword.lowercase(Locale.getDefault()))
                ) {
                    return true
                }
            }
            return false
        }
    }


}