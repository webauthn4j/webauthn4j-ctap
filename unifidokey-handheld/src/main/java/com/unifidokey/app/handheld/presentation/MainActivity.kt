package com.unifidokey.app.handheld.presentation

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.view.MenuItem
import androidx.activity.addCallback
import androidx.appcompat.app.ActionBarDrawerToggle
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.Toolbar
import androidx.core.view.GravityCompat
import androidx.drawerlayout.widget.DrawerLayout
import androidx.navigation.NavController
import androidx.navigation.fragment.NavHostFragment
import com.google.android.gms.oss.licenses.OssLicensesMenuActivity
import com.google.android.material.bottomnavigation.BottomNavigationView
import com.google.android.material.navigation.NavigationBarView
import com.google.android.material.navigation.NavigationView
import com.google.firebase.analytics.FirebaseAnalytics
import com.unifidokey.R
import com.unifidokey.app.UnifidoKeyComponent
import com.unifidokey.app.handheld.UnifidoKeyHandHeldApplication
import com.unifidokey.app.handheld.presentation.util.KeepScreenOnUtil
import com.unifidokey.core.service.BLEService
import com.unifidokey.core.service.BTHIDService
import com.unifidokey.core.service.NFCService
import com.unifidokey.driver.transport.CtapBLEAndroidServiceContextualAdapter
import com.unifidokey.driver.transport.CtapBTHIDAndroidServiceContextualAdapter
import com.unifidokey.driver.transport.CtapNFCAndroidServiceAdapter
import org.slf4j.LoggerFactory


class MainActivity : AppCompatActivity(), NavigationView.OnNavigationItemSelectedListener,
    NavigationBarView.OnItemSelectedListener {
    private val logger = LoggerFactory.getLogger(MainActivity::class.java)

    private lateinit var unifidoKeyHandHeldApplication: UnifidoKeyHandHeldApplication
    private lateinit var unifidoKeyComponent: UnifidoKeyComponent

    private val navHostFragment by lazy {
        supportFragmentManager.findFragmentById(R.id.nav_host_fragment) as NavHostFragment
    }
    private val navController: NavController by lazy {
        navHostFragment.navController
    }
    private val toolbar: Toolbar by lazy { findViewById(R.id.toolbar) }
    private val drawer: DrawerLayout by lazy { findViewById(R.id.drawer_layout) }
    private val navigationView: NavigationView by lazy { findViewById(R.id.navigation) }
    private val bottomNavigationView: BottomNavigationView by lazy { findViewById(R.id.bottom_navigation) }


    private lateinit var nfcService: NFCService
    private lateinit var bleService: BLEService
    private lateinit var bthidService: BTHIDService

    private lateinit var nfcServiceContextualAdapter: CtapNFCAndroidServiceAdapter
    private lateinit var bleServiceContextualAdapter: CtapBLEAndroidServiceContextualAdapter
    private lateinit var bthidServiceContextualAdapter: CtapBTHIDAndroidServiceContextualAdapter

    private var firebaseAnalytics: FirebaseAnalytics? = null


    //region## Lifecycle event handlers ##
    override fun onCreate(savedInstanceState: Bundle?) {
        logger.debug("onCreate")
        super.onCreate(savedInstanceState)

        unifidoKeyHandHeldApplication = application as UnifidoKeyHandHeldApplication
        unifidoKeyComponent = unifidoKeyHandHeldApplication.unifidoKeyComponent

        nfcServiceContextualAdapter = unifidoKeyComponent.nfcServiceContextualAdapter
        bleServiceContextualAdapter = unifidoKeyComponent.bleServiceContextualAdapter
        bthidServiceContextualAdapter = unifidoKeyComponent.bthidServiceContextualAdapter
        nfcService = unifidoKeyComponent.nfcService
        bleService = unifidoKeyComponent.bleService
        bthidService = unifidoKeyComponent.bthidService

        // initialize components
        initializeFirebaseAnalytics()
        if(bleServiceContextualAdapter.isBLEAdapterAvailable){
            bleServiceContextualAdapter.startService()
            bleServiceContextualAdapter.bindService(this)
        }
        if(bthidServiceContextualAdapter.isBTHIDAdapterAvailable){
            bthidServiceContextualAdapter.startService()
            bthidServiceContextualAdapter.bindService(this)
        }

        // initialize view
        setContentView(R.layout.main_activity)
        initializeToolbar()
        initializeDrawer()
        initializeNavigationView()
        initializeBottomNavigationView()

        navController.addOnDestinationChangedListener { _, destination, _ ->
            val navMenuId = when (destination.id) {
                R.id.homeFragment -> R.id.nav_home
                R.id.credentialListFragment -> R.id.nav_credentials
                R.id.credentialDetailsFragment -> R.id.nav_credentials
                R.id.historyFragment -> R.id.nav_history
                else -> throw IllegalStateException("Unknown destination id is provided.")
            }
            bottomNavigationView.selectedItemId = navMenuId
        }

        onBackPressedDispatcher.addCallback(this) {
            if (drawer.isDrawerOpen(GravityCompat.START)) {
                drawer.closeDrawer(GravityCompat.START)
            }
        }
    }


    override fun onDestroy() {
        logger.debug("onDestroy")
        super.onDestroy()
        bleServiceContextualAdapter.unbindService(this)
        bthidServiceContextualAdapter.unbindService(this)
    }

    override fun onStart() {
        logger.debug("onStart")
        super.onStart()
    }

    override fun onResume() {
        logger.debug("onResume")
        super.onResume()
        KeepScreenOnUtil.configureKeepScreenOnFlag(this)
    }

    override fun onStop() {
        logger.debug("onStop")
        super.onStop()
    }

    //endregion
    //region## User action event handlers ##

    override fun onNavigationItemSelected(item: MenuItem): Boolean {
        // Handle navigation view item clicks here.
        val id = item.itemId
        val intent: Intent
        when (id) {
            R.id.nav_home -> {
                if (navController.currentDestination!!.id != R.id.homeFragment) {
                    navController.navigate(R.id.homeFragment)
                }
            }
            R.id.nav_credentials -> {
                if (navController.currentDestination!!.id != R.id.credentialListFragment && navController.currentDestination!!.id != R.id.credentialDetailsFragment) {
                    navController.navigate(R.id.credentialListFragment)
                }
            }
            R.id.nav_history -> {
                if (navController.currentDestination!!.id != R.id.historyFragment) {
                    navController.navigate(R.id.historyFragment)
                }
            }
            R.id.nav_settings -> {
                intent = Intent(this, SettingsActivity::class.java)
                startActivity(intent)
            }
            R.id.nav_licenses -> {
                intent = Intent(this, OssLicensesMenuActivity::class.java)
                startActivity(intent)
            }
            R.id.nav_help -> {
                intent = Intent(Intent.ACTION_VIEW, Uri.parse("https://docs.unifidokey.com/en/"))
                startActivity(intent)
            }
            R.id.nav_about -> {
                intent = Intent(this, AboutActivity::class.java)
                startActivity(intent)
            }
            else -> {
            }
        }
        drawer.closeDrawer(GravityCompat.START)
        return true
    }
    //endregion

    // Methods
    private fun initializeFirebaseAnalytics(){
        if(!UnifidoKeyHandHeldApplication.isOssFlavor){
            firebaseAnalytics = FirebaseAnalytics.getInstance(this)
        }
    }

    private fun initializeNavigationView() {
        navigationView.setNavigationItemSelectedListener(this)
    }

    private fun initializeBottomNavigationView() {
        bottomNavigationView.setOnItemSelectedListener(this)
    }

    private fun initializeToolbar() {
        setSupportActionBar(toolbar)
    }

    private fun initializeDrawer() {
        val toggle = ActionBarDrawerToggle(
            this, drawer, toolbar, R.string.nav_drawer_open, R.string.nav_drawer_close
        )
        drawer.addDrawerListener(toggle)
        toggle.syncState()
    }

}