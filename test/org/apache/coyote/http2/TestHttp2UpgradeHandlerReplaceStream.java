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
package org.apache.coyote.http2;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

import org.junit.Assert;
import org.junit.Test;

/*
 * Once a stream has been replaced (closed and recycled), header fields decoded
 * by the connection's HPACK decoder must no longer be emitted to that stream.
 */
public class TestHttp2UpgradeHandlerReplaceStream {

    private static final String TRAILER_NAME = "x-trailer";
    private static final String TRAILER_VALUE = "from-stream-3";


    /*
     * Control test. Ensures the trailer used in the other tests is delivered
     * to an active stream so the "not delivered" assertions are meaningful.
     */
    @Test
    public void testTrailerDeliveredToActiveStream() throws Exception {
        Http2UpgradeHandler handler = createHandler();
        Stream stream = startTrailerHeaders(handler, 3);

        handler.getHpackDecoder().decode(createTrailerBlock());

        Assert.assertEquals(TRAILER_VALUE, stream.getCoyoteRequest().getTrailerFields().get(TRAILER_NAME));
    }


    /*
     * The stream is closed and replaced after the start of its trailer
     * headers but before the remaining trailer headers (e.g. in CONTINUATION
     * frames) have been decoded.
     */
    @Test
    public void testReplaceStreamClearsHeaderEmitter() throws Exception {
        Http2UpgradeHandler handler = createHandler();
        Stream stream = startTrailerHeaders(handler, 3);
        Assert.assertSame(stream, handler.getHpackDecoder().getHeaderEmitter());

        // Processing of the stream completes and the stream is replaced
        stream.recycle();

        Assert.assertSame(Http2UpgradeHandler.HEADER_SINK, handler.getHpackDecoder().getHeaderEmitter());

        // Remaining trailer headers arrive
        handler.getHpackDecoder().decode(createTrailerBlock());

        Assert.assertNull(stream.getCoyoteRequest().getTrailerFields().get(TRAILER_NAME));
    }


    /*
     * Replacing a stream must not change the header emitter if headers are
     * currently being emitted to a different stream.
     */
    @Test
    public void testReplaceOtherStreamKeepsHeaderEmitter() throws Exception {
        Http2UpgradeHandler handler = createHandler();
        Stream stream3 = startTrailerHeaders(handler, 3);
        Stream stream5 = startTrailerHeaders(handler, 5);
        Assert.assertSame(stream5, handler.getHpackDecoder().getHeaderEmitter());

        stream3.recycle();

        Assert.assertSame(stream5, handler.getHpackDecoder().getHeaderEmitter());

        handler.getHpackDecoder().decode(createTrailerBlock());

        Assert.assertEquals(TRAILER_VALUE, stream5.getCoyoteRequest().getTrailerFields().get(TRAILER_NAME));
        Assert.assertNull(stream3.getCoyoteRequest().getTrailerFields().get(TRAILER_NAME));
    }


    private static Http2UpgradeHandler createHandler() {
        Http2Protocol protocol = new Http2Protocol();
        protocol.setAllowedTrailerHeaders(TRAILER_NAME);
        return new Http2UpgradeHandler(protocol, null, null);
    }


    /*
     * Same calls as Http2Parser for a HEADERS frame with the request headers
     * followed by a HEADERS frame with the trailer headers.
     */
    private static Stream startTrailerHeaders(Http2UpgradeHandler handler, int streamId) throws Exception {
        HpackDecoder hpackDecoder = handler.getHpackDecoder();
        Stream stream = (Stream) handler.headersStart(streamId, false);
        hpackDecoder.setHeaderEmitter(stream);
        hpackDecoder.setHeaderEmitter(handler.headersStart(streamId, true));
        return stream;
    }


    /*
     * HPACK: Literal Header Field without Indexing - New Name (RFC 7541,
     * section 6.2.2) without Huffman encoding.
     */
    private static ByteBuffer createTrailerBlock() {
        byte[] name = TRAILER_NAME.getBytes(StandardCharsets.ISO_8859_1);
        byte[] value = TRAILER_VALUE.getBytes(StandardCharsets.ISO_8859_1);
        ByteBuffer buffer = ByteBuffer.allocate(3 + name.length + value.length);
        buffer.put((byte) 0x00);
        buffer.put((byte) name.length);
        buffer.put(name);
        buffer.put((byte) value.length);
        buffer.put(value);
        buffer.flip();
        return buffer;
    }
}
