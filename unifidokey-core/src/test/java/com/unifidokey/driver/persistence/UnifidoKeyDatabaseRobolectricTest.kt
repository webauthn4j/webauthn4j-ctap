package com.unifidokey.driver.persistence

import android.content.Context
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import com.google.common.truth.Truth
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class UnifidoKeyDatabaseRobolectricTest {
    private lateinit var target: UnifidoKeyDatabase

    @Before
    fun setup() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        target = Room.inMemoryDatabaseBuilder(context, UnifidoKeyDatabase::class.java)
            .allowMainThreadQueries().build()
    }

    @Test
    fun getRelyingPartyDao_test() {
        val relyingPartyDao = target.relyingPartyDao
        Truth.assertThat(relyingPartyDao).isNotNull()
    }
}
