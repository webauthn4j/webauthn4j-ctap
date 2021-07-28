package com.unifidokey.app.handheld.presentation

import androidx.preference.Preference.SummaryProvider
import androidx.preference.SwitchPreferenceCompat
import com.unifidokey.R

class NFCPreferenceSummaryProvider : SummaryProvider<SwitchPreferenceCompat> {
    override fun provideSummary(preference: SwitchPreferenceCompat): CharSequence {
        return when {
            preference.isEnabled -> {
                when {
                    preference.isChecked -> preference.context.resources.getString(R.string.summary_nfc_support_on)
                    else -> preference.context.resources.getString(R.string.summary_nfc_support_off)
                }
            }
            else -> preference.context.resources.getString(R.string.summary_nfc_support_disabled)
        }
    }
}