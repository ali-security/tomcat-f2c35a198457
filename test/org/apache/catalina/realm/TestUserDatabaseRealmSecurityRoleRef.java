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
package org.apache.catalina.realm;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import org.apache.catalina.Role;
import org.apache.catalina.User;
import org.apache.catalina.connector.Request;
import org.apache.catalina.core.StandardContext;
import org.apache.catalina.core.StandardWrapper;
import org.apache.catalina.users.MemoryUserDatabase;
import org.apache.tomcat.unittest.TesterResponse;
import org.apache.tomcat.util.descriptor.web.SecurityConstraint;

/*
 * The UserDatabaseRealm in this version overrides hasRole(Wrapper, ...) so it
 * needs the same separation of the Context role mapping from the Servlet
 * security-role-ref as RealmBase.
 */
public class TestUserDatabaseRealmSecurityRoleRef {

    private UserDatabaseRealm realm;
    private StandardContext context;
    private StandardWrapper wrapper;
    private User user;

    @Before
    public void setup() {
        MemoryUserDatabase database = new MemoryUserDatabase("test");
        Role role = database.createRole("otherRole", null);
        user = database.createUser("testUser", "testPwd", null);
        user.addRole(role);

        realm = new UserDatabaseRealm();
        realm.database = database;

        context = new StandardContext();
        context.addSecurityRole("otherRole");
        context.addRoleMapping("mappedRole", "otherRole");
        context.setRealm(realm);

        wrapper = new StandardWrapper();
        wrapper.setName("servlet");
        wrapper.setParent(context);
        // The servlet code uses "refRole" for the application role "otherRole"
        wrapper.addSecurityReference("refRole", "otherRole");
        // A security-role-ref may link to a role that is mapped by the Context
        wrapper.addSecurityReference("refToMappedRole", "mappedRole");
    }


    @Test
    public void testHasRoleIgnoresSecurityRoleRef() {
        Assert.assertTrue(realm.hasRole(wrapper, user, "otherRole"));
        // security-role-ref is only for HttpServletRequest.isUserInRole()
        Assert.assertFalse(realm.hasRole(wrapper, user, "refRole"));
        Assert.assertFalse(realm.hasRole(wrapper, user, "refToMappedRole"));
    }


    @Test
    public void testHasRoleAppliesContextRoleMapping() {
        Assert.assertTrue(realm.hasRole(wrapper, user, "mappedRole"));
        Assert.assertTrue(realm.hasRole(wrapper, new GenericPrincipal("testUser", "testPwd", null, user),
                "mappedRole"));
        // No wrapper, no role mapping
        Assert.assertFalse(realm.hasRole(null, user, "mappedRole"));
    }


    @Test
    public void testIsUserInRoleAppliesSecurityRoleRef() {
        Request request = createRequest();

        Assert.assertTrue(request.isUserInRole("otherRole"));
        Assert.assertTrue(request.isUserInRole("refRole"));
        Assert.assertTrue(request.isUserInRole("mappedRole"));
        Assert.assertTrue(request.isUserInRole("refToMappedRole"));
        Assert.assertFalse(request.isUserInRole("unknownRole"));
    }


    @Test
    public void testHasResourcePermissionIgnoresSecurityRoleRef() throws Exception {
        Request request = createRequest();

        // A constraint naming the security-role-ref name must not be met
        SecurityConstraint constraint = new SecurityConstraint();
        constraint.setAuthConstraint(true);
        constraint.addAuthRole("refRole");
        Assert.assertFalse(realm.hasResourcePermission(request, new TesterResponse(),
                new SecurityConstraint[] { constraint }, context));

        // A constraint naming a role mapped by the Context is met
        constraint = new SecurityConstraint();
        constraint.setAuthConstraint(true);
        constraint.addAuthRole("mappedRole");
        Assert.assertTrue(realm.hasResourcePermission(request, new TesterResponse(),
                new SecurityConstraint[] { constraint }, context));
    }


    private Request createRequest() {
        Request request = new Request(null);
        request.getMappingData().context = context;
        request.getMappingData().wrapper = wrapper;
        request.setUserPrincipal(user);
        return request;
    }
}
