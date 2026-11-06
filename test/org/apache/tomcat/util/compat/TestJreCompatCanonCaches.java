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

import java.lang.reflect.ReflectPermission;
import java.security.Permission;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.junit.After;
import org.junit.Assert;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;

import org.apache.tomcat.unittest.TesterLogValidationFilter;

/**
 * Tests the CVE-2024-56337 canonical file name cache handling in {@link JreCompat} on the JVMs where the cache is
 * enabled by default and can be disabled with reflection (Java 8 to 11).
 */
public class TestJreCompatCanonCaches {

    private final Logger logger = Logger.getLogger(JreCompat.class.getName());

    @Before
    public void setUp() throws Exception {
        Assume.assumeTrue(TesterCanonCaches.isCanonCachesFieldMutable());
        Assume.assumeFalse(TesterCanonCaches.isUseCanonCachesSetOnCommandLine());
        TesterCanonCaches.reset();
    }


    @After
    public void tearDown() throws Exception {
        logger.setFilter(null);
        if (TesterCanonCaches.isCanonCachesFieldMutable()) {
            TesterCanonCaches.reset();
        }
    }


    @Test
    public void testDisableCanonCaches() throws Exception {
        JreCompat jreCompat = JreCompat.getInstance();

        Assert.assertTrue(TesterCanonCaches.isJvmCanonCachesEnabled());
        Assert.assertFalse(jreCompat.isCanonCachesDisabled());

        Assert.assertTrue(jreCompat.disableCanonCaches());

        Assert.assertFalse(TesterCanonCaches.isJvmCanonCachesEnabled());
        Assert.assertTrue(jreCompat.isCanonCachesDisabled());
    }


    @Test
    public void testDisableCanonCachesReflectionDenied() throws Exception {
        TesterLogValidationFilter filter = new TesterLogValidationFilter(Level.WARNING,
                "Unable to create a reference to the java.io.FileSystem.useCanonCaches static field", null);
        logger.setFilter(filter);

        boolean result;
        System.setSecurityManager(new DenySuppressAccessChecks());
        try {
            // Must not throw: the failure is logged and reported via the return value
            result = JreCompat.getInstance().disableCanonCaches();
        } finally {
            System.setSecurityManager(null);
        }

        Assert.assertFalse(result);
        Assert.assertEquals(1, filter.getMessageCount());
        Assert.assertTrue(TesterCanonCaches.isJvmCanonCachesEnabled());
        Assert.assertFalse(JreCompat.getInstance().isCanonCachesDisabled());
    }


    /*
     * Denies Field.setAccessible(true) the way a restrictive SecurityManager (or, on Java 9+, a module that is not
     * open) does.
     */
    private static class DenySuppressAccessChecks extends SecurityManager {

        @Override
        public void checkPermission(Permission perm) {
            if (perm instanceof ReflectPermission && "suppressAccessChecks".equals(perm.getName())) {
                throw new SecurityException(perm.toString());
            }
        }

        @Override
        public void checkPermission(Permission perm, Object context) {
            checkPermission(perm);
        }
    }
}
