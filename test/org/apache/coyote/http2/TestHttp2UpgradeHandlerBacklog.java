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

import org.junit.Assert;
import org.junit.Test;

/*
 * A stream that is reset while it is waiting in the connection flow control
 * backlog must not leave its allocation request, or an allocation it was
 * granted but did not use, in the backlog once the stream is replaced.
 */
public class TestHttp2UpgradeHandlerBacklog {

    @Test
    public void testResetStreamRemovedFromBacklog() throws Exception {
        Http2UpgradeHandler handler = createHandlerWithEmptyConnectionWindow();

        // Connection window is empty so stream 3 is added to the backlog
        Stream stream3 = createStream(handler, 3);
        Assert.assertEquals(0, handler.reserveWindowSize(stream3, 1024, false));

        // The client resets stream 3 and the stream is then replaced
        stream3.receiveReset(Http2Error.CANCEL.getCode());
        stream3.recycle();

        // Nothing is waiting so the whole window update is available
        handler.incrementWindowSize(512);

        Stream stream5 = createStream(handler, 5);
        Assert.assertEquals(512, handler.reserveWindowSize(stream5, 1024, false));
    }


    @Test
    public void testResetStreamUnusedAllocationReturned() throws Exception {
        Http2UpgradeHandler handler = createHandlerWithEmptyConnectionWindow();

        // Connection window is empty so both streams are added to the backlog
        Stream stream3 = createStream(handler, 3);
        Stream stream5 = createStream(handler, 5);
        Assert.assertEquals(0, handler.reserveWindowSize(stream3, 1024, false));
        Assert.assertEquals(0, handler.reserveWindowSize(stream5, 1024, false));

        // The window update is shared between the two streams
        handler.incrementWindowSize(1024);

        // The client resets stream 3 before it uses its allocation and the
        // stream is then replaced
        stream3.receiveReset(Http2Error.CANCEL.getCode());
        stream3.recycle();

        // The allocation stream 3 did not use is available to stream 5
        Assert.assertEquals(1024, handler.reserveWindowSize(stream5, 1024, false));
    }


    @Test
    public void testResetParentOfBackloggedStream() throws Exception {
        doTestReplacedParentOfBackloggedStream(true, true);
    }


    @Test
    public void testCompletedParentOfBackloggedStream() throws Exception {
        doTestReplacedParentOfBackloggedStream(false, true);
    }


    @Test
    public void testBackloggedAfterParentReset() throws Exception {
        doTestReplacedParentOfBackloggedStream(true, false);
    }


    @Test
    public void testBackloggedAfterParentCompleted() throws Exception {
        doTestReplacedParentOfBackloggedStream(false, false);
    }


    @Test
    public void testBacklogReleasedAfterParentReplaced() throws Exception {
        Http2UpgradeHandler handler = createHandlerWithEmptyConnectionWindow();

        // Stream 5 depends on stream 3
        Stream stream3 = createStream(handler, 3);
        Stream stream5 = createStream(handler, 5);
        handler.reprioritise(5, 3, false, Constants.DEFAULT_WEIGHT);

        // Stream 3 completes and is replaced. Stream 5 is then added to the
        // backlog with the replacement of stream 3 as its parent.
        completeStream(stream3);
        stream3.recycle();
        Assert.assertEquals(0, handler.reserveWindowSize(stream5, 1024, false));

        // A window update larger than the backlog releases the whole backlog
        handler.incrementWindowSize(2048);
        Assert.assertEquals(1024, handler.reserveWindowSize(stream5, 1024, false));
    }


    @Test
    public void testBacklogReleasedAfterParentReset() throws Exception {
        Http2UpgradeHandler handler = createHandlerWithEmptyConnectionWindow();

        // Stream 5 depends on stream 3
        Stream stream3 = createStream(handler, 3);
        Stream stream5 = createStream(handler, 5);
        handler.reprioritise(5, 3, false, Constants.DEFAULT_WEIGHT);

        // Connection window is empty so stream 5 is added to the backlog
        Assert.assertEquals(0, handler.reserveWindowSize(stream5, 1024, false));

        // Stream 3 is reset and replaced while stream 5 is in the backlog
        stream3.receiveReset(Http2Error.CANCEL.getCode());
        stream3.recycle();

        // A window update larger than the backlog releases the whole backlog
        handler.incrementWindowSize(2048);
        Assert.assertEquals(1024, handler.reserveWindowSize(stream5, 1024, false));
    }


    @Test
    public void testRecycleTwice() throws Exception {
        Http2UpgradeHandler handler = createHandlerWithEmptyConnectionWindow();

        // Stream 5 depends on stream 3
        Stream stream3 = createStream(handler, 3);
        Stream stream5 = createStream(handler, 5);
        handler.reprioritise(5, 3, false, Constants.DEFAULT_WEIGHT);

        stream3.receiveReset(Http2Error.CANCEL.getCode());
        stream3.recycle();
        // A second attempt to recycle the stream is ignored
        stream3.recycle();

        Assert.assertEquals(0, handler.reserveWindowSize(stream5, 1024, false));
        handler.incrementWindowSize(512);
        Assert.assertEquals(512, handler.reserveWindowSize(stream5, 1024, false));
    }


    /*
     * Stream 5 depends on stream 3. Stream 3 is reset by the client or
     * completes, and is replaced, either while stream 5 is waiting in the
     * backlog or before stream 5 is added to it. A window update that is
     * smaller than the backlog must still reach stream 5.
     */
    private void doTestReplacedParentOfBackloggedStream(boolean reset, boolean backlogFirst)
            throws Exception {
        Http2UpgradeHandler handler = createHandlerWithEmptyConnectionWindow();

        Stream stream3 = createStream(handler, 3);
        Stream stream5 = createStream(handler, 5);
        handler.reprioritise(5, 3, false, Constants.DEFAULT_WEIGHT);

        if (backlogFirst) {
            // Connection window is empty so stream 5 is added to the backlog
            // (with stream 3 and the connection as its parents)
            Assert.assertEquals(0, handler.reserveWindowSize(stream5, 1024, false));
        }

        if (reset) {
            stream3.receiveReset(Http2Error.CANCEL.getCode());
        } else {
            completeStream(stream3);
        }
        stream3.recycle();

        if (!backlogFirst) {
            Assert.assertEquals(0, handler.reserveWindowSize(stream5, 1024, false));
        }

        // The window update is smaller than the backlog. It is allocated to
        // stream 5, the only stream that is waiting.
        handler.incrementWindowSize(512);
        Assert.assertEquals(512, handler.reserveWindowSize(stream5, 1024, false));

        // The rest of the request is allocated by the next window update
        handler.incrementWindowSize(512);
        Assert.assertEquals(512, handler.reserveWindowSize(stream5, 512, false));
    }


    private static void completeStream(Stream stream) {
        // Request received in full and response sent in full
        stream.state.receivedStartOfHeaders();
        stream.state.receivedEndOfStream();
        stream.state.sentHeaders();
        stream.state.sentEndOfStream();
        Assert.assertFalse(stream.isActive());
    }


    private static Http2UpgradeHandler createHandlerWithEmptyConnectionWindow() {
        Http2UpgradeHandler handler = new Http2UpgradeHandler(new Http2Protocol(), null, null);
        handler.decrementWindowSize((int) handler.getWindowSize());
        Assert.assertEquals(0, handler.getWindowSize());
        return handler;
    }


    private static Stream createStream(Http2UpgradeHandler handler, int streamId) throws Exception {
        return (Stream) handler.headersStart(streamId, true);
    }
}
