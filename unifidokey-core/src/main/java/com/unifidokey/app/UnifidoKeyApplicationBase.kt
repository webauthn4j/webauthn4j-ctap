package com.unifidokey.app

import android.app.Application

abstract class UnifidoKeyApplicationBase<T : UnifidoKeyComponent> : Application(),
    UnifidoKeyApplication<T> {

    override lateinit var unifidoKeyComponent: T

    override fun onCreate() {
        super.onCreate()
        unifidoKeyComponent = createUnifidoKeyComponent()
    }

    protected abstract fun createUnifidoKeyComponent(): T
}