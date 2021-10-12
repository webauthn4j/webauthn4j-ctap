package com.unifidokey.gradle.util;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class VersionCodeUtil {

    public static Integer getVersionCodeFromVersionString(String versionString) {
        Matcher matcher = Pattern.compile("([0-9]+)\\.([0-9]+)\\.([0-9]+)(-SNAPSHOT|\\.RELEASE)").matcher(versionString);
        if (!matcher.find()) {
            throw new IllegalArgumentException("versionString doesn't conform format contract.");
        }
        int major = Integer.parseInt(matcher.group(1));
        int minor = Integer.parseInt(matcher.group(2));
        int patch = Integer.parseInt(matcher.group(3));
        return major * 10000 + minor * 100 + patch;
    }
}
