package com.unifidokey.driver.persistence.dao

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.unifidokey.core.config.ConfigNotFoundException
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class PreferenceDaoRobolectricTest {
    private lateinit var target: PreferenceDao

    @Before
    fun setUp() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        target = PreferenceDao(context)
    }

    @Test(expected = ConfigNotFoundException::class)
    fun loadBoolean_test() {
        target.loadBoolean("noEntry")
    }
}