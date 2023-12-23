package com.unifidokey.app.handheld.presentation

import android.annotation.SuppressLint
import android.content.Context
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.BaseAdapter
import android.widget.TextView
import com.unifidokey.R

internal class CredentialSelectorDialogAdapter(
    context: Context,
    private val credentialViewModels: List<CredentialViewModel>?
) : BaseAdapter() {

    private val layoutInflater: LayoutInflater =
        context.getSystemService(Context.LAYOUT_INFLATER_SERVICE) as LayoutInflater

    override fun getCount(): Int {
        return credentialViewModels!!.size
    }

    override fun getItem(position: Int): CredentialViewModel {
        return credentialViewModels!![position]
    }

    override fun getItemId(position: Int): Long {
        return position.toLong()
    }

    override fun getView(position: Int, convertView: View?, parent: ViewGroup?): View {
        @SuppressLint("ViewHolder") val view =
            layoutInflater.inflate(R.layout.credential_list_item_layout, parent, false)
        val displayNameView = view.findViewById<TextView>(R.id.displayName_view)
        displayNameView.text = getItem(position).displayName
        val usernameView = view.findViewById<TextView>(R.id.username_view)
        usernameView.text = getItem(position).username
        return view
    }

}