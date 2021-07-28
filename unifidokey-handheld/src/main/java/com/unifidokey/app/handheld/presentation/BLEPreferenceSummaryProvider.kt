package com.unifidokey.app.handheld.presentation

import androidx.preference.Preference.SummaryProvider
import androidx.preference.SwitchPreferenceCompat
import com.unifidokey.R

class BLEPreferenceSummaryProvider : SummaryProvider<SwitchPreferenceCompat> {
    override fun provideSummary(preference: SwitchPreferenceCompat): CharSequence {
        return when {
            preference.isEnabled -> when {
                preference.isChecked -> preference.context.resources.getString(R.string.summary_ble_support_on)
                else -> preference.context.resources.getString(R.string.summary_ble_support_off)
            }
            else -> preference.context.resources.getString(R.string.summary_ble_support_disabled)
        }
    }
}