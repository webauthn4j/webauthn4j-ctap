package com.unifidokey.app.handheld.presentation

import android.os.Bundle
import android.view.MenuItem
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.ViewModelProvider
import com.unifidokey.R
import com.unifidokey.app.handheld.presentation.helper.KeepScreenOnHelper
import org.slf4j.LoggerFactory

class SettingsActivity : AppCompatActivity() {
    private val logger = LoggerFactory.getLogger(SettingsActivity::class.java)
    private lateinit var viewModel: SettingsViewModel

    //region## Lifecycle event handlers ##
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // initialize viewModel
        initializeViewModel()

        // initialize views
        setContentView(R.layout.settings_activity)
        initializeFragment()
        initializeActionBar()
    }

    override fun onResume() {
        super.onResume()
        KeepScreenOnHelper.configureKeepScreenOnFlag(this)
    }

    //endregion

    //region## User action event handlers ##
    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        when (item.itemId) {
            android.R.id.home -> {
                finish()
                return true
            }
        }
        return super.onOptionsItemSelected(item)
    }
    //endregion

    private fun initializeFragment() {
        supportFragmentManager
            .beginTransaction()
            .replace(R.id.settings, SettingsFragment(this, viewModel))
            .commit()
    }

    private fun initializeActionBar() {
        val actionBar = supportActionBar
        actionBar?.setDisplayHomeAsUpEnabled(true)
    }

    private fun initializeViewModel() {
        viewModel = ViewModelProvider(this).get(SettingsViewModel::class.java)
    }
}