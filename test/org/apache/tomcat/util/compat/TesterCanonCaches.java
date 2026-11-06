/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.tomcat.util.compat;

import java.lang.management.ManagementFactory;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.Optional;

/**
 * Test helper for the canonical file name cache (CVE-2024-56337) handling in {@link JreCompat}. It reads and resets
 * the JVM wide {@code java.io.FileSystem.useCanonCaches} field and the state {@link JreCompat} caches about it so each
 * test starts from the Java 8 to 11 default: the cache is enabled and Tomcat has not looked at it yet.
 */
public class TesterCanonCaches {

    private static final Field USE_CANON_CACHES;

    static {
        Field f = null;
        try {
            f = Class.forName("java.io.FileSystem").getDeclaredField("useCanonCaches");
            if (Modifier.isFinal(f.getModifiers())) {
                // Java 12 to 20. Disabled by default and cannot be changed with plain reflection.
                f = null;
            } else {
                f.setAccessible(true);
            }
        } catch (ReflectiveOperationException | RuntimeException e) {
            // Java 21+ (no cache) or reflection not permitted
            f = null;
        }
        USE_CANON_CACHES = f;
    }


    /**
     * @return {@code true} if this JVM has the Java 8 to 11 form of the cache: a non-final static field that can be
     *         read and changed with reflection
     */
    public static boolean isCanonCachesFieldMutable() {
        return USE_CANON_CACHES != null;
    }


    /**
     * @return {@code true} if the JVM command line sets {@code sun.io.useCanonCaches}
     */
    public static boolean isUseCanonCachesSetOnCommandLine() {
        for (String arg : ManagementFactory.getRuntimeMXBean().getInputArguments()) {
            if (arg.startsWith(JreCompat.USE_CANON_CACHES_CMD_ARG)) {
                return true;
            }
        }
        return false;
    }


    /**
     * @return the current value of {@code java.io.FileSystem.useCanonCaches}
     *
     * @throws Exception if the field cannot be read
     */
    public static boolean isJvmCanonCachesEnabled() throws Exception {
        return USE_CANON_CACHES.getBoolean(null);
    }


    /**
     * Re-enable the JVM cache (the Java 8 to 11 default) and clear what {@link JreCompat} has cached about it.
     *
     * @throws Exception if the field cannot be written
     */
    public static void reset() throws Exception {
        USE_CANON_CACHES.setBoolean(null, true);
        synchronized (JreCompat.canonCachesDisabledLock) {
            JreCompat.canonCachesDisabled = null;
        }
        synchronized (JreCompat.useCanonCachesFieldLock) {
            JreCompat.useCanonCachesField = null;
        }
    }


    /**
     * Simulate a JVM on which {@link JreCompat} cannot obtain a usable reference to
     * {@code java.io.FileSystem.useCanonCaches} (e.g. reflection denied).
     */
    public static void makeFieldUnavailable() {
        synchronized (JreCompat.useCanonCachesFieldLock) {
            JreCompat.useCanonCachesField = Optional.empty();
        }
    }
}
