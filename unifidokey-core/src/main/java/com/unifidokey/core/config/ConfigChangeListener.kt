package com.unifidokey.core.config

fun interface ConfigChangeListener<T> {
    fun onConfigChange(newValue: T)
}
