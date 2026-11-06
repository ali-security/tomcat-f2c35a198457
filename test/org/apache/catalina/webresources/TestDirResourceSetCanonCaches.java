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
package org.apache.catalina.webresources;

import java.io.File;
import java.nio.file.Files;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.junit.After;
import org.junit.Assert;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;

import org.apache.catalina.LifecycleState;
import org.apache.catalina.startup.ExpandWar;
import org.apache.tomcat.unittest.TesterLogValidationFilter;
import org.apache.tomcat.util.compat.JreCompat;
import org.apache.tomcat.util.compat.TesterCanonCaches;

/**
 * Tests the CVE-2024-56337 check in {@link DirResourceSet#initInternal()}.
 */
public class TestDirResourceSetCanonCaches {

    private static final String DISABLED =
            "Disabled the global canonical file name cache to protect against CVE-2024-56337";
    private static final String EXPOSED = "The WebResourceSet may be exposed to CVE-2024-56337.";

    private final Logger logger = Logger.getLogger(DirResourceSet.class.getName());

    private File dir;


    @Before
    public void setUp() throws Exception {
        dir = Files.createTempDirectory("tomcat-canon-caches").toFile();
    }


    @After
    public void tearDown() throws Exception {
        logger.setFilter(null);
        if (TesterCanonCaches.isCanonCachesFieldMutable()) {
            TesterCanonCaches.reset();
        }
        ExpandWar.delete(dir);
    }


    @Test
    public void testWritableResourceSetDisablesCanonCaches() throws Exception {
        Assume.assumeTrue(TesterCanonCaches.isCanonCachesFieldMutable());
        Assume.assumeFalse(TesterCanonCaches.isUseCanonCachesSetOnCommandLine());
        TesterCanonCaches.reset();

        TesterLogValidationFilter filter = new TesterLogValidationFilter(Level.WARNING, DISABLED, null);
        logger.setFilter(filter);

        // A read-only resource set is not exposed so the cache is left alone
        DirResourceSet readOnly = new DirResourceSet();
        readOnly.setRoot(new TesterWebResourceRoot());
        readOnly.setWebAppMount("/");
        readOnly.setBase(dir.getAbsolutePath());
        readOnly.setReadOnly(true);
        readOnly.start();
        Assert.assertEquals(LifecycleState.STARTED, readOnly.getState());
        Assert.assertTrue(TesterCanonCaches.isJvmCanonCachesEnabled());
        Assert.assertEquals(0, filter.getMessageCount());

        // A writable resource set (the default) is exposed so the cache is disabled
        DirResourceSet writable = new DirResourceSet(new TesterWebResourceRoot(), "/", dir.getAbsolutePath(), "/");
        Assert.assertEquals(LifecycleState.STARTED, writable.getState());
        Assert.assertFalse(TesterCanonCaches.isJvmCanonCachesEnabled());
        Assert.assertTrue(JreCompat.getInstance().isCanonCachesDisabled());
        Assert.assertEquals(1, filter.getMessageCount());

        // Once the cache is disabled, starting another writable resource set does not log again
        DirResourceSet writable2 = new DirResourceSet(new TesterWebResourceRoot(), "/", dir.getAbsolutePath(), "/");
        Assert.assertEquals(LifecycleState.STARTED, writable2.getState());
        Assert.assertEquals(1, filter.getMessageCount());
    }


    /*
     * Seal: upstream throws IllegalStateException here and the web application does not start. The sealed version logs
     * a warning and the resource set starts.
     */
    @Test
    public void testWritableResourceSetStartsIfCanonCachesCannotBeDisabled() throws Exception {
        Assume.assumeTrue(TesterCanonCaches.isCanonCachesFieldMutable());
        Assume.assumeFalse(TesterCanonCaches.isUseCanonCachesSetOnCommandLine());
        TesterCanonCaches.reset();
        TesterCanonCaches.makeFieldUnavailable();

        TesterLogValidationFilter filter = new TesterLogValidationFilter(Level.WARNING, EXPOSED, null);
        logger.setFilter(filter);

        DirResourceSet writable = new DirResourceSet(new TesterWebResourceRoot(), "/", dir.getAbsolutePath(), "/");

        Assert.assertEquals(LifecycleState.STARTED, writable.getState());
        Assert.assertEquals(1, filter.getMessageCount());
        Assert.assertTrue(TesterCanonCaches.isJvmCanonCachesEnabled());
        Assert.assertFalse(JreCompat.getInstance().isCanonCachesDisabled());
    }
}
