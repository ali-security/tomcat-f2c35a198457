/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.catalina.realm;

import java.security.Principal;
import java.sql.Connection;
import java.util.List;

import org.junit.Assert;
import org.junit.Test;

import org.apache.catalina.LifecycleException;
import org.apache.juli.logging.LogFactory;

/*
 * Upstream runs these tests against an embedded Derby database. Derby is not
 * part of this build so TesterRealmDatabase is used instead.
 */
public class TestDataSourceRealm {

    protected static class TesterDataSourceRealm extends DataSourceRealm {
        protected final TesterRealmDatabase database;
        protected volatile boolean available = true;
        public TesterDataSourceRealm(TesterRealmDatabase database) {
            this.database = database;
        }
        @Override
        protected Connection open() {
            // Replace DataSource use and JNDI access with the tester database
            if (!available) {
                return null;
            }
            return database.getConnection();
        }
        @Override
        protected void initInternal() throws LifecycleException {
            // Avoid heavy lifecycle and JMX, however container log is needed
            containerLog = LogFactory.getLog(TestDataSourceRealm.class);
        }
    }

    private TesterDataSourceRealm db;

    private static TesterRealmDatabase createDatabase(boolean roles) {
        TesterRealmDatabase database = new TesterRealmDatabase();
        database.addUser("tomcat", "password");
        database.addUser("random", "password");
        if (roles) {
            database.addUserRole("tomcat", "admin");
            database.addUserRole("tomcat", "foo");
        }
        return database;
    }

    @Test
    public void testRealm() throws Exception {

        db = new TesterDataSourceRealm(createDatabase(true));
        db.setUserTable("users");
        db.setUserNameCol("user_name");
        db.setUserCredCol("user_pass");
        db.setUserRoleTable("user_roles");
        db.setRoleNameCol("role_name");

        db.start();

        Principal p = db.authenticate("tomcat", "bar");
        Assert.assertNull(p);

        p = db.authenticate("blabla", "bar");
        Assert.assertNull(p);

        p = db.authenticate("tomcat", "password");
        Assert.assertTrue(p instanceof GenericPrincipal);
        GenericPrincipal gp = (GenericPrincipal) p;
        Assert.assertTrue(gp.hasRole("foo"));
        Assert.assertTrue(gp.hasRole("admin"));
        Assert.assertFalse(gp.hasRole("manager"));

        p = db.getPrincipal("tomcat");
        Assert.assertTrue(p instanceof GenericPrincipal);
        gp = (GenericPrincipal) p;
        Assert.assertTrue(gp.hasRole("foo"));
        Assert.assertTrue(gp.hasRole("admin"));
        Assert.assertFalse(gp.hasRole("manager"));

        String pass = db.getPassword("tomcat");
        Assert.assertEquals("password", pass);

        List<String> roles = db.getRoles("tomcat");
        Assert.assertEquals(2, roles.size());

        p = db.getPrincipal("blabla");
        Assert.assertNull(p);

        p = db.getPrincipal("random");
        Assert.assertTrue(p instanceof GenericPrincipal);
        gp = (GenericPrincipal) p;
        Assert.assertEquals(0, gp.getRoles().length);

        db.stop();
    }

    @Test
    public void testRealmWithoutRoleStore() throws Exception {

        db = new TesterDataSourceRealm(createDatabase(false));
        db.setUserTable("users");
        db.setUserNameCol("user_name");
        db.setUserCredCol("user_pass");

        db.start();

        // Default strict mode with no role store. Authentication of a valid
        // user must succeed with an empty role list rather than fail.
        Principal p = db.authenticate("tomcat", "bar");
        Assert.assertNull(p);

        p = db.authenticate("tomcat", "password");
        Assert.assertTrue(p instanceof GenericPrincipal);
        GenericPrincipal gp = (GenericPrincipal) p;
        Assert.assertEquals(0, gp.getRoles().length);

        p = db.getPrincipal("tomcat");
        Assert.assertTrue(p instanceof GenericPrincipal);
        gp = (GenericPrincipal) p;
        Assert.assertEquals(0, gp.getRoles().length);

        List<String> roles = db.getRoles("tomcat");
        Assert.assertNotNull(roles);
        Assert.assertEquals(0, roles.size());

        db.stop();
    }

    @Test
    public void testRoleLookupFailure() throws Exception {

        TesterRealmDatabase database = createDatabase(true);
        db = new TesterDataSourceRealm(database);
        db.setUserTable("users");
        db.setUserNameCol("user_name");
        db.setUserCredCol("user_pass");
        db.setUserRoleTable("user_roles");
        db.setRoleNameCol("role_name");

        db.start();

        database.setFailRoleQueries(true);

        // A failed role lookup must fail authentication rather than return a
        // Principal without roles
        Assert.assertNull(db.authenticate("tomcat", "password"));
        Assert.assertNull(db.getPrincipal("tomcat"));

        database.setFailRoleQueries(false);

        Assert.assertNotNull(db.authenticate("tomcat", "password"));
        Assert.assertNotNull(db.getPrincipal("tomcat"));

        db.stop();
    }

    @Test
    public void testDatabaseUnavailable() throws Exception {

        db = new TesterDataSourceRealm(createDatabase(true));
        db.setUserTable("users");
        db.setUserNameCol("user_name");
        db.setUserCredCol("user_pass");
        db.setUserRoleTable("user_roles");
        db.setRoleNameCol("role_name");

        db.start();

        db.available = false;

        // No Principal may be returned if the database cannot be reached
        Assert.assertNull(db.authenticate("tomcat", "password"));
        Assert.assertNull(db.getPrincipal("tomcat"));

        db.stop();
    }
}
