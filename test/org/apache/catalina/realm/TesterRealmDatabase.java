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
import java.sql.Connection;
import java.sql.Driver;
import java.sql.DriverPropertyInfo;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * A minimal in-memory stand-in for the database used by the JDBC based realms
 * in the realm unit tests. It only understands the statements those realms
 * generate, i.e. {@code SELECT <column> FROM <table> WHERE <column> = ?}, for
 * a {@code users} table (columns {@code user_name}, {@code user_pass}) and a
 * {@code user_roles} table (columns {@code user_name}, {@code role_name}).
 * Any other statement, including one built from an unset table or column
 * name, is rejected with an {@link SQLException} as a real database would.
 */
public class TesterRealmDatabase {

    private static final Pattern SELECT = Pattern.compile("SELECT (\\S+) FROM (\\S+) WHERE (\\S+) = \\?");

    /*
     * Database used by connections created via TesterDriver
     */
    private static volatile TesterRealmDatabase driverDatabase;

    private final Map<String,String> users = new HashMap<>();
    private final Map<String,List<String>> userRoles = new HashMap<>();
    private volatile boolean failRoleQueries = false;


    public static void setDriverDatabase(TesterRealmDatabase database) {
        driverDatabase = database;
    }


    public synchronized void addUser(String username, String password) {
        users.put(username, password);
    }


    public synchronized void addUserRole(String username, String role) {
        List<String> roles = userRoles.get(username);
        if (roles == null) {
            roles = new ArrayList<>();
            userRoles.put(username, roles);
        }
        roles.add(role);
    }


    /**
     * @param failRoleQueries {@code true} if executing a role query should
     *                        fail with an {@link SQLException}
     */
    public void setFailRoleQueries(boolean failRoleQueries) {
        this.failRoleQueries = failRoleQueries;
    }


    public Connection getConnection() {
        return (Connection) Proxy.newProxyInstance(TesterRealmDatabase.class.getClassLoader(),
                new Class<?>[] { Connection.class }, new ConnectionHandler());
    }


    private synchronized List<String> query(boolean roleQuery, String username) throws SQLException {
        if (roleQuery) {
            if (failRoleQueries) {
                throw new SQLException("Simulated role query failure");
            }
            List<String> roles = userRoles.get(username);
            if (roles == null) {
                return Collections.emptyList();
            }
            return new ArrayList<>(roles);
        } else {
            String password = users.get(username);
            if (password == null) {
                return Collections.emptyList();
            }
            return Collections.singletonList(password);
        }
    }


    private PreparedStatement prepareStatement(String sql) throws SQLException {
        Matcher m = SELECT.matcher(sql == null ? "" : sql);
        if (!m.matches() || !"user_name".equals(m.group(3))) {
            throw new SQLException("Invalid statement [" + sql + "]");
        }
        boolean roleQuery;
        if ("users".equals(m.group(2)) && "user_pass".equals(m.group(1))) {
            roleQuery = false;
        } else if ("user_roles".equals(m.group(2)) && "role_name".equals(m.group(1))) {
            roleQuery = true;
        } else {
            throw new SQLException("Unknown table or column in statement [" + sql + "]");
        }
        return (PreparedStatement) Proxy.newProxyInstance(TesterRealmDatabase.class.getClassLoader(),
                new Class<?>[] { PreparedStatement.class }, new StatementHandler(roleQuery));
    }


    private static Object handleObjectMethod(Object proxy, Method method, Object[] args) {
        switch (method.getName()) {
            case "hashCode":
                return Integer.valueOf(System.identityHashCode(proxy));
            case "equals":
                return Boolean.valueOf(proxy == args[0]);
            case "toString":
                return proxy.getClass().getName() + "@" + Integer.toHexString(System.identityHashCode(proxy));
            default:
                return null;
        }
    }


    private class ConnectionHandler implements InvocationHandler {

        private boolean autoCommit = true;
        private boolean closed = false;

        @Override
        public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
            Object result = handleObjectMethod(proxy, method, args);
            if (result != null) {
                return result;
            }
            switch (method.getName()) {
                case "prepareStatement":
                    if (args.length == 1) {
                        return prepareStatement((String) args[0]);
                    }
                    break;
                case "getAutoCommit":
                    return Boolean.valueOf(autoCommit);
                case "setAutoCommit":
                    autoCommit = ((Boolean) args[0]).booleanValue();
                    return null;
                case "commit":
                case "rollback":
                    return null;
                case "close":
                    closed = true;
                    return null;
                case "isClosed":
                    return Boolean.valueOf(closed);
                default:
                    break;
            }
            throw new SQLFeatureNotSupportedException(method.getName());
        }
    }


    private class StatementHandler implements InvocationHandler {

        private final boolean roleQuery;
        private String username;
        private boolean closed = false;

        StatementHandler(boolean roleQuery) {
            this.roleQuery = roleQuery;
        }

        @Override
        public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
            Object result = handleObjectMethod(proxy, method, args);
            if (result != null) {
                return result;
            }
            switch (method.getName()) {
                case "setString":
                    username = (String) args[1];
                    return null;
                case "setNull":
                    username = null;
                    return null;
                case "executeQuery":
                    if (args == null || args.length == 0) {
                        final List<String> values = query(roleQuery, username);
                        return Proxy.newProxyInstance(TesterRealmDatabase.class.getClassLoader(),
                                new Class<?>[] { ResultSet.class }, new ResultSetHandler(values));
                    }
                    break;
                case "close":
                    closed = true;
                    return null;
                case "isClosed":
                    return Boolean.valueOf(closed);
                default:
                    break;
            }
            throw new SQLFeatureNotSupportedException(method.getName());
        }
    }


    private static class ResultSetHandler implements InvocationHandler {

        private final List<String> values;
        private int row = -1;

        ResultSetHandler(List<String> values) {
            this.values = values;
        }

        @Override
        public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
            Object result = handleObjectMethod(proxy, method, args);
            if (result != null) {
                return result;
            }
            switch (method.getName()) {
                case "next":
                    row++;
                    return Boolean.valueOf(row < values.size());
                case "getString":
                    if (args[0] instanceof Integer && ((Integer) args[0]).intValue() == 1) {
                        return values.get(row);
                    }
                    break;
                case "close":
                    return null;
                default:
                    break;
            }
            throw new SQLFeatureNotSupportedException(method.getName());
        }
    }


    /**
     * JDBC driver for the realms that are configured with a driver name and a
     * connection URL. Connections use the database registered via
     * {@link TesterRealmDatabase#setDriverDatabase(TesterRealmDatabase)}.
     */
    public static class TesterDriver implements Driver {

        @Override
        public Connection connect(String url, Properties info) throws SQLException {
            TesterRealmDatabase database = driverDatabase;
            if (database == null) {
                throw new SQLException("No database");
            }
            return database.getConnection();
        }

        @Override
        public boolean acceptsURL(String url) throws SQLException {
            return true;
        }

        @Override
        public DriverPropertyInfo[] getPropertyInfo(String url, Properties info) throws SQLException {
            return new DriverPropertyInfo[0];
        }

        @Override
        public int getMajorVersion() {
            return 1;
        }

        @Override
        public int getMinorVersion() {
            return 0;
        }

        @Override
        public boolean jdbcCompliant() {
            return false;
        }

        @Override
        public Logger getParentLogger() throws SQLFeatureNotSupportedException {
            throw new SQLFeatureNotSupportedException();
        }
    }
}
