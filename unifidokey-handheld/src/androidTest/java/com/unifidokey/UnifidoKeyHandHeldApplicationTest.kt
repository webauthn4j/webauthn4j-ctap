package com.unifidokey

import androidx.test.core.app.ApplicationProvider
import com.unifidokey.app.handheld.UnifidoKeyHandHeldApplication
import org.junit.Before
import org.junit.Test

class UnifidoKeyHandHeldApplicationTest {
    private var target: UnifidoKeyHandHeldApplication? = null

    @Before
    fun setup() {
        target = ApplicationProvider.getApplicationContext()
    }

    @Test
    fun test() {
    }
}