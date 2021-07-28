package com.unifidokey.app.handheld.presentation

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.databinding.DataBindingUtil
import androidx.fragment.app.Fragment
import androidx.lifecycle.ViewModelProvider
import com.unifidokey.R
import com.unifidokey.databinding.AboutFragmentBinding

class AboutFragment : Fragment() {

    //region## Lifecycle event handlers ##
    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        val binding: AboutFragmentBinding =
            DataBindingUtil.inflate(inflater, R.layout.about_fragment, container, false)
        val viewModel = ViewModelProvider(this).get(AboutViewModel::class.java)
        binding.viewModel = viewModel
        return binding.root
    }
    //endregion
}