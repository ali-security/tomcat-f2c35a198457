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
package org.apache.catalina.authenticator;

import java.util.HashMap;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.message.AuthException;
import javax.security.auth.message.AuthStatus;
import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.MessagePolicy;
import javax.security.auth.message.config.AuthConfigFactory;
import javax.security.auth.message.module.ServerAuthModule;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.After;
import org.junit.Assert;
import org.junit.Test;

import org.apache.catalina.Context;
import org.apache.catalina.authenticator.jaspic.SimpleAuthConfigProvider;
import org.apache.catalina.startup.TesterServlet;
import org.apache.catalina.startup.Tomcat;
import org.apache.catalina.startup.TomcatBaseTest;
import org.apache.tomcat.util.buf.ByteChunk;

/**
 * Tests for the Jakarta Authentication (JASPIC) handling in
 * {@link AuthenticatorBase}.
 */
public class TestAuthenticatorBaseJaspic extends TomcatBaseTest {

    private static final String MODULE_KEY = "org.apache.catalina.authenticator.jaspic.ServerAuthModule.1";

    private String registrationID = null;


    @After
    public void removeRegistration() {
        if (registrationID != null) {
            AuthConfigFactory.getFactory().removeRegistration(registrationID);
            registrationID = null;
        }
    }


    /*
     * CVE-2024-52316. A ServerAuthContext that fails with an exception
     * without setting an HTTP status code must not result in a successful
     * (200) response.
     */
    @Test
    public void testValidateRequestAuthException() throws Exception {
        registerDefaultProvider(TesterServerAuthModuleException.class);

        Tomcat tomcat = getTomcatInstance();
        Context ctx = tomcat.addContext("", null);
        Tomcat.addServlet(ctx, "servlet", new TesterServlet());
        ctx.addServletMappingDecoded("/", "servlet");

        tomcat.start();

        ByteChunk bc = new ByteChunk();
        int rc = getUrl("http://localhost:" + getPort() + "/", bc, null);

        Assert.assertEquals(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, rc);
        Assert.assertNotEquals("OK", bc.toString());
    }


    private void registerDefaultProvider(Class<? extends ServerAuthModule> moduleClass) {
        Map<String,String> properties = new HashMap<>();
        properties.put(MODULE_KEY, moduleClass.getName());
        SimpleAuthConfigProvider provider = new SimpleAuthConfigProvider(properties, null);
        registrationID = AuthConfigFactory.getFactory().registerConfigProvider(provider, null, null, "Test");
    }


    public abstract static class TesterServerAuthModuleBase implements ServerAuthModule {

        protected CallbackHandler handler;

        @Override
        public void initialize(MessagePolicy requestPolicy, MessagePolicy responsePolicy,
                CallbackHandler handler, @SuppressWarnings("rawtypes") Map options) throws AuthException {
            this.handler = handler;
        }

        @SuppressWarnings("rawtypes")
        @Override
        public Class[] getSupportedMessageTypes() {
            return new Class[] { HttpServletRequest.class, HttpServletResponse.class };
        }

        @Override
        public AuthStatus secureResponse(MessageInfo messageInfo, Subject serviceSubject) throws AuthException {
            return AuthStatus.SEND_SUCCESS;
        }

        @Override
        public void cleanSubject(MessageInfo messageInfo, Subject subject) throws AuthException {
            // NO-OP
        }
    }


    public static class TesterServerAuthModuleException extends TesterServerAuthModuleBase {

        @Override
        public AuthStatus validateRequest(MessageInfo messageInfo, Subject clientSubject, Subject serviceSubject)
                throws AuthException {
            // Fail without setting an HTTP status code
            throw new AuthException();
        }
    }
}
