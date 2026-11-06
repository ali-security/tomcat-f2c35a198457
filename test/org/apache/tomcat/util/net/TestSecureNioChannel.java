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
package org.apache.tomcat.util.net;

import java.io.Closeable;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

/**
 * Checks that the flag {@link SecureNioChannel} uses to track a pending TLS
 * handshake wrap is reset so that state from one connection (or from a
 * previous wrap) is not carried over.
 */
public class TestSecureNioChannel {

    private ServerSocketChannel serverChannel;
    private SocketChannel clientChannel;
    private SocketChannel acceptedChannel;
    private SecureNioChannel secureChannel;


    @Before
    public void setUp() throws Exception {
        serverChannel = ServerSocketChannel.open();
        serverChannel.socket().bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0));
        clientChannel = SocketChannel.open(new InetSocketAddress(InetAddress.getLoopbackAddress(),
                serverChannel.socket().getLocalPort()));
        acceptedChannel = serverChannel.accept();
        secureChannel = new SecureNioChannel(new SocketBufferHandler(8192, 8192, false),
                new NioSelectorPool(), new NioEndpoint());
    }


    @After
    public void tearDown() throws Exception {
        close(acceptedChannel);
        close(clientChannel);
        close(serverChannel);
    }


    @Test
    public void testResetClearsNeedHandshakeWrap() throws Exception {
        secureChannel.reset(clientChannel, null);

        // Previous connection left a handshake wrap pending
        secureChannel.needHandshakeWrap = true;
        secureChannel.handshakeComplete = true;

        // Channel is recycled for a new connection
        secureChannel.reset(clientChannel, null);

        Assert.assertFalse(secureChannel.handshakeComplete);
        Assert.assertFalse("needHandshakeWrap not cleared by reset()", secureChannel.needHandshakeWrap);
    }


    @Test
    public void testGatheringWriteClearsNeedHandshakeWrap() throws Exception {
        prepareForWrite();

        ByteBuffer[] srcs = new ByteBuffer[] { ByteBuffer.wrap("Hello".getBytes(StandardCharsets.UTF_8)) };
        secureChannel.write(srcs, 0, srcs.length);

        Assert.assertFalse("needHandshakeWrap not cleared by gathering write()", secureChannel.needHandshakeWrap);
    }


    @Test
    public void testWriteClearsNeedHandshakeWrap() throws Exception {
        prepareForWrite();

        secureChannel.write(ByteBuffer.wrap("Hello".getBytes(StandardCharsets.UTF_8)));

        Assert.assertFalse("needHandshakeWrap not cleared by write()", secureChannel.needHandshakeWrap);
    }


    private void prepareForWrite() throws Exception {
        secureChannel.reset(clientChannel, null);

        SSLEngine engine = SSLContext.getDefault().createSSLEngine();
        engine.setUseClientMode(true);
        secureChannel.sslEngine = engine;

        // No pending network output
        secureChannel.netOutBuffer.clear();
        secureChannel.netOutBuffer.limit(0);

        // A handshake wrap is pending
        secureChannel.needHandshakeWrap = true;
    }


    private static void close(Closeable closeable) {
        if (closeable != null) {
            try {
                closeable.close();
            } catch (IOException ioe) {
                // Ignore
            }
        }
    }
}
