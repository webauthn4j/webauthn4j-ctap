package com.unifidokey.app.handheld.presentation

import androidx.preference.MultiSelectListPreference
import androidx.preference.Preference.SummaryProvider

class AlgPreferenceSummaryProvider : SummaryProvider<MultiSelectListPreference> {

    override fun provideSummary(preference: MultiSelectListPreference): CharSequence {
        val entryValues = listOf(*preference.entryValues)
        val entries = preference.entries
        val list = preference.values.map { value: String ->
            val index = entryValues.indexOf(value)
            entries[index]
        }
        return java.lang.String.join(", ", list)
    }
}