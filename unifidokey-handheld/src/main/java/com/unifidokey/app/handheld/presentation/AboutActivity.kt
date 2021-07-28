package com.unifidokey.app.handheld.presentation

import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import com.unifidokey.R
import com.unifidokey.app.handheld.presentation.helper.KeepScreenOnHelper

class AboutActivity : AppCompatActivity() {

    //region## Lifecycle event handlers ##
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.about_activity)
        val actionbar = supportActionBar!!
        actionbar.setHomeButtonEnabled(true)
        actionbar.setDisplayHomeAsUpEnabled(true)
        if (savedInstanceState == null) {
            supportFragmentManager.beginTransaction()
                .replace(R.id.container, AboutFragment())
                .commitNow()
        }
    }

    override fun onResume() {
        super.onResume()
        KeepScreenOnHelper.configureKeepScreenOnFlag(this)
    }
    //endregion

    //region## User action event handlers ##
    //endregion
}