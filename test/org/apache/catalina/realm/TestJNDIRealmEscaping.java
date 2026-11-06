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

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Deque;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;

import javax.naming.NameParser;
import javax.naming.NamingEnumeration;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.LdapName;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import org.apache.juli.logging.LogFactory;

/*
 * The upstream tests for these changes (TestJNDIRealmIntegration) need the
 * UnboundID LDAP SDK which is not part of this build. These tests record the
 * DNs, search bases and search filters that JNDIRealm passes to the directory
 * instead.
 */
public class TestJNDIRealmEscaping {

    private static final String USER_PATTERN = "cn={0},ou=people,dc=example,dc=com";
    private static final String USER_SEARCH = "cn={0}";
    private static final String USER_BASE = "ou=people,dc=example,dc=com";
    private static final String ROLE_SEARCH = "(|(member={0})(memberUid={1})(roleId={2}))";
    private static final String ROLE_BASE = "ou=groups,dc=example,dc=com";

    private JNDIRealm realm;
    private RecordingDirContext recorder;


    @Before
    public void setup() {
        realm = new JNDIRealm();
        realm.containerLog = LogFactory.getLog(TestJNDIRealmEscaping.class);
        recorder = new RecordingDirContext();
    }


    @Test
    public void testUserPatternAttributeValueEscaping() throws Exception {
        realm.setUserPattern(USER_PATTERN);
        JNDIRealm.JNDIConnection connection = createConnection();

        Assert.assertNotNull(realm.getUserByPattern(connection, "t;", null, new String[] { "cn" }, 0));
        Assert.assertNotNull(realm.getUserByPattern(connection, "admin,ou=admins", null, new String[] { "cn" }, 0));

        Assert.assertEquals(Arrays.asList(
                "cn=t\\3B,ou=people,dc=example,dc=com",
                "cn=admin\\2Cou=admins,ou=people,dc=example,dc=com"),
                recorder.attributeLookups);
    }


    @Test
    public void testUserSearchFilterEscaping() throws Exception {
        realm.setUserSearch(USER_SEARCH);
        realm.setUserBase(USER_BASE);
        JNDIRealm.JNDIConnection connection = createConnection();

        Assert.assertNull(realm.getUserBySearch(connection, "t*", new String[] { "cn" }));
        Assert.assertNull(realm.getUserBySearch(connection, "t)(cn=*", new String[] { "cn" }));

        Assert.assertEquals(Arrays.asList(USER_BASE, USER_BASE), recorder.searchBases);
        Assert.assertEquals(Arrays.asList(
                "cn=t\\2a",
                "cn=t\\29\\28cn=\\2a"),
                recorder.searchFilters);
    }


    @Test
    public void testRoleSearchFilterEscaping() throws Exception {
        configureRoleSearch(ROLE_SEARCH, ROLE_BASE, false);
        JNDIRealm.JNDIConnection connection = createConnection();

        JNDIRealm.User user = new JNDIRealm.User(
                "t;*", "cn=t\\3B\\2A,ou=people,dc=example,dc=com", null, null, "id(*)");
        List<String> roles = realm.getRoles(connection, user);

        Assert.assertEquals(0, roles.size());
        Assert.assertEquals(Collections.singletonList(ROLE_BASE), recorder.searchBases);
        Assert.assertEquals(Collections.singletonList(
                "(|(member=cn=t\\5c3B\\5c2A,ou=people,dc=example,dc=com)" +
                "(memberUid=t\\5c3B\\2a)(roleId=id\\28\\2a\\29))"),
                recorder.searchFilters);
    }


    @Test
    public void testRoleSearchWithoutUserRoleAttributeValue() throws Exception {
        configureRoleSearch(ROLE_SEARCH, ROLE_BASE, false);
        JNDIRealm.JNDIConnection connection = createConnection();

        // No value for userRoleAttribute. This must not trigger an NPE
        JNDIRealm.User user = new JNDIRealm.User(
                "test", "cn=test,ou=people,dc=example,dc=com", null, null, null);
        List<String> roles = realm.getRoles(connection, user);

        Assert.assertEquals(0, roles.size());
        // MessageFormat renders the missing value as "null", as it always has
        Assert.assertEquals(Collections.singletonList(
                "(|(member=cn=test,ou=people,dc=example,dc=com)(memberUid=test)(roleId=null))"),
                recorder.searchFilters);
    }


    @Test
    public void testNestedRoleSearchFilterEscaping() throws Exception {
        configureRoleSearch(ROLE_SEARCH, ROLE_BASE, true);
        JNDIRealm.JNDIConnection connection = createConnection();

        // Direct group, then no nested group
        recorder.addSearchResult(new SearchResult("cn=Test\\3CGroup*2", null,
                new BasicAttributes("cn", "Test<Group*2", true)));
        recorder.addSearchResult();

        JNDIRealm.User user = new JNDIRealm.User(
                "test", "cn=test,ou=people,dc=example,dc=com", null, null, "test");
        List<String> roles = realm.getRoles(connection, user);

        Assert.assertEquals(Collections.singletonList("Test<Group*2"), roles);
        Assert.assertEquals(Arrays.asList(ROLE_BASE, ROLE_BASE), recorder.searchBases);
        Assert.assertEquals(Arrays.asList(
                "(|(member=cn=test,ou=people,dc=example,dc=com)(memberUid=test)(roleId=test))",
                "(|(member=cn=Test\\5c<Group\\2a2,ou=groups,dc=example,dc=com)" +
                "(memberUid=Test\\5c3CGroup\\2a2)(roleId=Test\\5c3CGroup\\2a2))"),
                recorder.searchFilters);
    }


    @Test
    public void testNestedRoleSearchWithPatternRoleBase() throws Exception {
        configureRoleSearch("member={0}", "{3},ou=people,dc=example,dc=com", true);
        JNDIRealm.JNDIConnection connection = createConnection();

        // Direct group, nested group, then no further nested group
        recorder.addSearchResult(new SearchResult("cn=TestGroup4", null,
                new BasicAttributes("cn", "TestGroup4", true)));
        recorder.addSearchResult(new SearchResult("cn=TestGroup5", null,
                new BasicAttributes("cn", "TestGroup5", true)));
        recorder.addSearchResult();

        // As returned by the directory, using \<char> escaping
        JNDIRealm.User user = new JNDIRealm.User(
                "testsub", "cn=testsub,ou=s\\;ub,ou=people,dc=example,dc=com", null, null, "testsub");
        List<String> roles = realm.getRoles(connection, user);

        Assert.assertEquals(new HashSet<>(Arrays.asList("TestGroup4", "TestGroup5")), new HashSet<>(roles));
        Assert.assertEquals(2, roles.size());

        // The substituted value is converted to \<hex><hex> escaping and the
        // substituted base is used for every search
        String base = "ou=s\\3Bub,ou=people,dc=example,dc=com";
        Assert.assertEquals(Arrays.asList(base, base, base), recorder.searchBases);
        // Group DNs are composed from the substituted base
        Assert.assertEquals(Arrays.asList(
                "member=cn=testsub,ou=s\\5c;ub,ou=people,dc=example,dc=com",
                "member=cn=TestGroup4,ou=s\\5c;ub,ou=people,dc=example,dc=com",
                "member=cn=TestGroup5,ou=s\\5c;ub,ou=people,dc=example,dc=com"),
                recorder.searchFilters);
    }


    private void configureRoleSearch(String roleSearch, String roleBase, boolean roleNested) {
        realm.setRoleSearch(roleSearch);
        realm.setRoleBase(roleBase);
        realm.setRoleName("cn");
        realm.setRoleNested(roleNested);
    }


    private JNDIRealm.JNDIConnection createConnection() {
        JNDIRealm.JNDIConnection connection = realm.create();
        connection.context = (DirContext) Proxy.newProxyInstance(TestJNDIRealmEscaping.class.getClassLoader(),
                new Class<?>[] { DirContext.class }, recorder);
        return connection;
    }


    /*
     * Records the names, bases and filters used to access the directory.
     * Searches return the queued results in order, then no results.
     */
    private static class RecordingDirContext implements InvocationHandler {

        private final List<String> attributeLookups = new ArrayList<>();
        private final List<String> searchBases = new ArrayList<>();
        private final List<String> searchFilters = new ArrayList<>();
        private final Deque<List<SearchResult>> searchResults = new ArrayDeque<>();

        void addSearchResult(SearchResult... results) {
            searchResults.add(Arrays.asList(results));
        }

        @Override
        public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
            String name = method.getName();
            if ("getAttributes".equals(name) && args.length == 2 && args[0] instanceof String) {
                attributeLookups.add((String) args[0]);
                return new BasicAttributes(true);
            } else if ("search".equals(name) && args.length == 3 && args[0] instanceof String &&
                    args[1] instanceof String) {
                searchBases.add((String) args[0]);
                searchFilters.add((String) args[1]);
                List<SearchResult> results = searchResults.poll();
                if (results == null) {
                    results = Collections.emptyList();
                }
                return new TesterNamingEnumeration(results);
            } else if ("getNameParser".equals(name)) {
                NameParser parser = LdapName::new;
                return parser;
            } else if ("getNameInNamespace".equals(name)) {
                return "";
            }
            throw new UnsupportedOperationException(name);
        }
    }


    private static class TesterNamingEnumeration implements NamingEnumeration<SearchResult> {

        private final Iterator<SearchResult> iterator;

        TesterNamingEnumeration(List<SearchResult> results) {
            iterator = results.iterator();
        }

        @Override
        public boolean hasMoreElements() {
            return iterator.hasNext();
        }

        @Override
        public SearchResult nextElement() {
            if (!iterator.hasNext()) {
                throw new NoSuchElementException();
            }
            return iterator.next();
        }

        @Override
        public SearchResult next() {
            return nextElement();
        }

        @Override
        public boolean hasMore() {
            return hasMoreElements();
        }

        @Override
        public void close() {
            // NO-OP
        }
    }
}
