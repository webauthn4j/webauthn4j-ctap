package com.unifidokey.app.handheld.presentation

import android.os.Bundle
import android.view.MenuItem
import androidx.appcompat.app.AppCompatActivity
import com.unifidokey.R
import com.unifidokey.app.handheld.presentation.util.KeepScreenOnUtil

class AboutActivity : AppCompatActivity() {

    //region## Lifecycle event handlers ##
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)


        // initialize views
        setContentView(R.layout.about_activity)

        initializeFragment()
        initializeActionBar()
    }

    override fun onResume() {
        super.onResume()
        KeepScreenOnUtil.configureKeepScreenOnFlag(this)
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
        supportFragmentManager.beginTransaction()
            .replace(R.id.container, AboutFragment())
            .commitNow()
    }

    private fun initializeActionBar() {
        val actionBar = supportActionBar
        actionBar?.setDisplayHomeAsUpEnabled(true)
    }
}