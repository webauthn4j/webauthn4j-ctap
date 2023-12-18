package com.unifidokey.gradle.util

import java.util.regex.Pattern

object VersionCodeUtil {
    fun getVersionCodeFromVersionString(versionString: String): Int {
        val matcher = Pattern.compile("([0-9]+)\\.([0-9]+)\\.([0-9]+)(-SNAPSHOT|\\.RELEASE)")
            .matcher(versionString)
        require(matcher.find()) { "versionString doesn't conform format contract." }
        val major = matcher.group(1).toInt()
        val minor = matcher.group(2).toInt()
        val patch = matcher.group(3).toInt()
        return major * 10000 + minor * 100 + patch
    }
}