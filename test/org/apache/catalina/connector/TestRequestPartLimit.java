/*
 *  Licensed to the Apache Software Foundation (ASF) under one or more
 *  contributor license agreements.  See the NOTICE file distributed with
 *  this work for additional information regarding copyright ownership.
 *  The ASF licenses this file to You under the Apache License, Version 2.0
 *  (the "License"); you may not use this file except in compliance with
 *  the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package org.apache.catalina.connector;

import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.MultipartConfigElement;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.Assert;
import org.junit.Test;

import org.apache.catalina.Context;
import org.apache.catalina.Wrapper;
import org.apache.catalina.startup.Tomcat;
import org.apache.catalina.startup.TomcatBaseTest;
import org.apache.tomcat.util.buf.ByteChunk;

/**
 * Tests the two limits added for CVE-2025-48976 and CVE-2025-48988 to protect
 * against multipart denial of service: {@code maxPartCount} bounds the total
 * number of parts in a multipart request and {@code maxPartHeaderSize} bounds
 * the number of header bytes permitted per part. Both default to the limits
 * that applied before they were configurable (10000 parts, matching the
 * default {@code maxParameterCount}, and 10240 header bytes per part), so the
 * tests of the CVE request shapes configure lower limits explicitly.
 */
public class TestRequestPartLimit extends TomcatBaseTest {

    private static final String CRLF = "\r\n";

    private static final String BOUNDARY = "TomcatMultipartBoundary";

    /**
     * The new Connector attributes default to the limits that applied before
     * they existed.
     */
    @Test
    public void testConnectorDefaults() {
        Connector connector = new Connector();
        Assert.assertEquals(10000, connector.getMaxPartCount());
        Assert.assertEquals(connector.getMaxParameterCount(), connector.getMaxPartCount());
        Assert.assertEquals(10240, connector.getMaxPartHeaderSize());
    }

    /**
     * A multipart request with more parts than {@code maxPartCount} must be
     * rejected even though it is within {@code maxParameterCount}.
     */
    @Test
    public void testMaxPartCountExceeded() throws Exception {
        StringBuilder body = new StringBuilder();
        // Five parts. maxPartCount is set to 2 below, so this is over the limit.
        addFields(body, 5);
        endBody(body);

        // maxParameterCount left generous (large) so the part count is the
        // limit that trips. maxPartCount = 2, maxPartHeaderSize left generous.
        String response = doMultipartRequest(1000, 2, 8192, toBytes(body));

        assertRejected(response, "IOException");
    }

    /**
     * A multipart request below {@code maxPartCount} must be accepted.
     */
    @Test
    public void testMaxPartCountNotExceeded() throws Exception {
        StringBuilder body = new StringBuilder();
        addFields(body, 2);
        endBody(body);

        String response = doMultipartRequest(1000, 5, 8192, toBytes(body));

        assertAccepted(response, 2);
    }

    /**
     * A multipart request with exactly {@code maxPartCount} parts must be
     * accepted.
     */
    @Test
    public void testMaxPartCountAtLimit() throws Exception {
        StringBuilder body = new StringBuilder();
        addFields(body, 5);
        endBody(body);

        String response = doMultipartRequest(1000, 5, 8192, toBytes(body));

        assertAccepted(response, 5);
    }

    /**
     * A multipart request with a part whose headers exceed
     * {@code maxPartHeaderSize} must be rejected.
     */
    @Test
    public void testMaxPartHeaderSizeExceeded() throws Exception {
        StringBuilder body = new StringBuilder();
        // A single part whose header section is padded well beyond the small
        // maxPartHeaderSize configured below.
        addFieldWithLongHeader(body, "p0", 5, 400);
        endBody(body);

        // maxPartHeaderSize = 128; the padded header above is larger than that.
        String response = doMultipartRequest(1000, 100, 128, toBytes(body));

        assertRejected(response, "IllegalStateException");
    }

    /**
     * A multipart request whose part headers are within
     * {@code maxPartHeaderSize} must be accepted.
     */
    @Test
    public void testMaxPartHeaderSizeNotExceeded() throws Exception {
        StringBuilder body = new StringBuilder();
        addField(body, "p0", 5);
        endBody(body);

        String response = doMultipartRequest(1000, 100, 512, toBytes(body));

        assertAccepted(response, 1);
    }

    /**
     * CVE-2025-48988: with {@code maxPartCount} lowered (here to 50) a request
     * with more parts is rejected even though maxParameterCount is left at its
     * default of 10000.
     */
    @Test
    public void testLoweredMaxPartCountExceeded() throws Exception {
        StringBuilder body = new StringBuilder();
        addFields(body, 51);
        endBody(body);

        String response = doMultipartRequest(10000, 50, 10240, toBytes(body));

        assertRejected(response, "IOException");
    }

    /**
     * A request with exactly the lowered maxPartCount parts must be accepted.
     */
    @Test
    public void testLoweredMaxPartCountAtLimit() throws Exception {
        StringBuilder body = new StringBuilder();
        addFields(body, 50);
        endBody(body);

        String response = doMultipartRequest(10000, 50, 10240, toBytes(body));

        assertAccepted(response, 50);
    }

    /**
     * CVE-2025-48976: with {@code maxPartHeaderSize} lowered (here to 512) a
     * part whose headers are larger than that, but well within the old
     * hard-coded 10kB limit, must be rejected.
     */
    @Test
    public void testLoweredMaxPartHeaderSizeExceeded() throws Exception {
        StringBuilder body = new StringBuilder();
        addFieldWithLongHeader(body, "p0", 5, 1024);
        endBody(body);

        String response = doMultipartRequest(10000, 10000, 512, toBytes(body));

        assertRejected(response, "IllegalStateException");
    }

    /**
     * CVE-2025-48976 / CVE-2025-48988 combined: many parts each carrying
     * large headers. With lowered limits every part is within the part-count
     * limit but the part headers exceed maxPartHeaderSize.
     */
    @Test
    public void testLoweredLimitsManyPartsWithLargeHeaders() throws Exception {
        StringBuilder body = new StringBuilder();
        for (int i = 0; i < 40; i++) {
            addFieldWithLongHeader(body, "p" + i, 5, 4096);
        }
        endBody(body);

        String response = doMultipartRequest(10000, 50, 512, toBytes(body));

        assertRejected(response, "IllegalStateException");
    }

    /**
     * With an out-of-the-box Connector a request that was accepted before the
     * limits existed - 100 parts, each with more than 2000 bytes of headers -
     * is still accepted.
     */
    @Test
    public void testDefaultsAcceptManyPartsWithLargeHeaders() throws Exception {
        StringBuilder body = new StringBuilder();
        for (int i = 0; i < 100; i++) {
            addFieldWithLongHeader(body, "p" + i, 5, 2000);
        }
        endBody(body);

        String response = doMultipartRequestWithDefaults(toBytes(body));

        assertAccepted(response, 100);
    }

    /**
     * With an out-of-the-box Connector a part whose headers are just within
     * the old hard-coded 10kB limit is still accepted.
     */
    @Test
    public void testDefaultMaxPartHeaderSizeNotExceeded() throws Exception {
        StringBuilder body = new StringBuilder();
        addFieldWithLongHeader(body, "p0", 5, 10000);
        endBody(body);

        String response = doMultipartRequestWithDefaults(toBytes(body));

        assertAccepted(response, 1);
    }

    /**
     * With an out-of-the-box Connector a part whose headers exceed the default
     * maxPartHeaderSize of 10240 bytes is rejected as a size limit violation.
     */
    @Test
    public void testDefaultMaxPartHeaderSizeExceeded() throws Exception {
        StringBuilder body = new StringBuilder();
        addFieldWithLongHeader(body, "p0", 5, 12000);
        endBody(body);

        String response = doMultipartRequestWithDefaults(toBytes(body));

        assertRejected(response, "IllegalStateException");
    }

    /**
     * The default maxPartCount still bounds the number of parts when
     * maxParameterCount is unlimited.
     */
    @Test
    public void testDefaultMaxPartCountWithUnlimitedParameters() throws Exception {
        StringBuilder body = new StringBuilder();
        addFields(body, 10001);
        endBody(body);

        Tomcat tomcat = getTomcatInstance();
        tomcat.getConnector().setMaxParameterCount(-1);
        String response = doMultipartRequest(tomcat, toBytes(body));

        assertRejected(response, "IOException");
    }

    /**
     * The parameter based limit still applies when it is lower than
     * maxPartCount.
     */
    @Test
    public void testMaxParameterCountLowerThanMaxPartCount() throws Exception {
        StringBuilder body = new StringBuilder();
        addFields(body, 4);
        endBody(body);

        String response = doMultipartRequest(3, 10000, 10240, toBytes(body));

        assertRejected(response, "IOException");
    }

    /**
     * maxPartCount still applies when maxParameterCount is unlimited.
     */
    @Test
    public void testMaxPartCountWithUnlimitedParameters() throws Exception {
        StringBuilder body = new StringBuilder();
        addFields(body, 3);
        endBody(body);

        String response = doMultipartRequest(-1, 2, 10240, toBytes(body));

        assertRejected(response, "IOException");
    }

    /**
     * Both limits may be disabled with -1.
     */
    @Test
    public void testLimitsDisabled() throws Exception {
        StringBuilder body = new StringBuilder();
        addFields(body, 60);
        addFieldWithLongHeader(body, "p60", 5, 12000);
        endBody(body);

        String response = doMultipartRequest(-1, -1, -1, toBytes(body));

        assertAccepted(response, 61);
    }

    private static void assertAccepted(String response, int partCount) {
        Assert.assertTrue("Request must be accepted: " + response,
                response.contains("getParts=OK"));
        Assert.assertTrue(response, response.contains("partCount=" + partCount + "\n") ||
                response.contains("partCount=" + partCount + "\r\n"));
    }

    private static void assertRejected(String response, String reason) {
        Assert.assertFalse("Request must be rejected: " + response,
                response.contains("getParts=OK"));
        Assert.assertTrue(response, response.contains("getParts=rejected"));
        Assert.assertTrue(response, response.contains("reason=" + reason));
    }

    private String doMultipartRequest(int maxParameterCount, int maxPartCount,
            int maxPartHeaderSize, byte[] body) throws Exception {
        Tomcat tomcat = getTomcatInstance();
        tomcat.getConnector().setMaxParameterCount(maxParameterCount);
        tomcat.getConnector().setMaxPartCount(maxPartCount);
        tomcat.getConnector().setMaxPartHeaderSize(maxPartHeaderSize);
        return doMultipartRequest(tomcat, body);
    }

    private String doMultipartRequestWithDefaults(byte[] body) throws Exception {
        // Leave all of the Connector limits at their default values
        return doMultipartRequest(getTomcatInstance(), body);
    }

    private String doMultipartRequest(Tomcat tomcat, byte[] body) throws Exception {

        Context ctx = tomcat.addContext("", TEMP_DIR);
        Wrapper w = Tomcat.addServlet(ctx, "parts", new PartsServlet());
        // No file-size, request-size or per-servlet parameter limits so that the
        // connector limits under test are the ones that trip.
        w.setMultipartConfigElement(new MultipartConfigElement(
                TEMP_DIR, -1, -1, -1));
        ctx.addServletMappingDecoded("/parts", "parts");

        tomcat.start();

        Map<String,List<String>> reqHead = new HashMap<>();
        reqHead.put("Content-Type",
                Collections.singletonList("multipart/form-data; boundary=" + BOUNDARY));

        ByteChunk out = new ByteChunk();
        postUrl(body, "http://localhost:" + getPort() + "/parts", out, reqHead, null);

        return out.toString();
    }

    private static void addFields(StringBuilder body, int count) {
        for (int i = 0; i < count; i++) {
            addField(body, "p" + i, 5);
        }
    }

    private static void addField(StringBuilder body, String name, int valueLength) {
        body.append("--").append(BOUNDARY).append(CRLF);
        body.append("Content-Disposition: form-data; name=\"").append(name).append('\"');
        body.append(CRLF).append(CRLF);
        appendContent(body, valueLength);
        body.append(CRLF);
    }

    private static void addFieldWithLongHeader(StringBuilder body, String name,
            int valueLength, int headerPadding) {
        body.append("--").append(BOUNDARY).append(CRLF);
        body.append("Content-Disposition: form-data; name=\"").append(name).append('\"');
        body.append(CRLF);
        // A custom, oversized header to push the header section past the limit.
        body.append("X-Padding: ");
        appendContent(body, headerPadding);
        body.append(CRLF).append(CRLF);
        appendContent(body, valueLength);
        body.append(CRLF);
    }

    private static void endBody(StringBuilder body) {
        body.append("--").append(BOUNDARY).append("--").append(CRLF);
    }

    private static void appendContent(StringBuilder body, int length) {
        for (int i = 0; i < length; i++) {
            body.append('x');
        }
    }

    private static byte[] toBytes(StringBuilder body) {
        return body.toString().getBytes(StandardCharsets.ISO_8859_1);
    }

    private static class PartsServlet extends HttpServlet {

        private static final long serialVersionUID = 1L;

        @Override
        protected void doPost(HttpServletRequest req, HttpServletResponse resp)
                throws ServletException, IOException {

            resp.setContentType("text/plain");
            resp.setCharacterEncoding("UTF-8");

            PrintWriter out = resp.getWriter();

            try {
                int count = req.getParts().size();
                out.println("getParts=OK");
                out.println("partCount=" + count);
            } catch (IllegalStateException ise) {
                // maxPartHeaderSize exceeded surfaces as a SizeException wrapped
                // in an IllegalStateException.
                out.println("getParts=rejected");
                out.println("reason=IllegalStateException");
            } catch (IOException ioe) {
                // maxPartCount exceeded surfaces as a FileUploadException wrapped
                // in an IOException.
                out.println("getParts=rejected");
                out.println("reason=IOException");
            }
        }
    }
}
