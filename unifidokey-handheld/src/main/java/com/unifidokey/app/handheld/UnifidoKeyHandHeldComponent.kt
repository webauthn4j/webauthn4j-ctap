package com.unifidokey.app.handheld

import com.unifidokey.app.UnifidoKeyComponent
import dagger.Component
import javax.inject.Singleton

@Singleton
@Component(modules = [UnifidoKeyHandHeldModule::class])
interface UnifidoKeyHandHeldComponent : UnifidoKeyComponent