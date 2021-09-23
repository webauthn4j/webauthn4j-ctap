package com.unifidokey.gradle.util;

import org.gradle.api.Project;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.Properties;

public class PropertyUtil {

    public static void load(Project project, Object path){
        // Load secret.properties if it exists
        File file = project.file(path);
        if (file.exists()) {
            Properties props = new Properties();
            try {
                props.load(new FileInputStream(file));
                props.forEach((key, value)->{
                    project.getExtensions().getExtraProperties().set(key.toString(), value);
                });
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }
    }
}
