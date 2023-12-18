package com.unifidokey.gradle.util

import org.gradle.api.Project
import java.io.FileInputStream
import java.io.IOException
import java.io.UncheckedIOException
import java.util.Properties

object PropertyUtil {
    fun load(project: Project, path: Any) {
        // Load secret.properties if it exists
        val file = project.file(path)
        if (file.exists()) {
            val props = Properties()
            try {
                props.load(FileInputStream(file))
                props.forEach { key: Any, value: Any? ->
                    project.extensions.extraProperties[key.toString()] = value
                }
            } catch (e: IOException) {
                throw UncheckedIOException(e)
            }
        }
    }
}