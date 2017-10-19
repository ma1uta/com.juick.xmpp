/*
 * Copyright (C) 2008-2017, Juick
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package com.juick.xmpp;

import com.juick.xmpp.extensions.StreamError;
import com.juick.xmpp.extensions.StreamFeatures;
import com.juick.xmpp.utils.XmlUtils;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.codec.digest.HmacUtils;
import org.apache.commons.text.RandomStringGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xmlpull.v1.XmlPullParser;
import rocks.xmpp.addr.Jid;

import java.io.EOFException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.SocketException;
import java.util.UUID;

/**
 * @author ugnich
 */
public class StreamServerDialback extends Stream {
    protected static final Logger logger = LoggerFactory.getLogger(StreamServerDialback.class);
    public static final String NS_TLS = "urn:ietf:params:xml:ns:xmpp-tls";
    public static final String NS_DB = "jabber:server:dialback";
    private boolean secured = false;

    public boolean streamReady = false;
    String checkSID = null;
    String dbKey = null;
    private String streamID;
    ConnectionListener connectionListener;
    RandomStringGenerator generator = new RandomStringGenerator.Builder().withinRange('a', 'z').build();

    public StreamServerDialback(Jid from, Jid to, InputStream is, OutputStream os, String checkSID, String dbKey) throws Exception {
        super(from, to, is, os);
        this.to = to;
        this.checkSID = checkSID;
        this.dbKey = dbKey;
        if (dbKey == null) {
            this.dbKey = generateKey(generator.generate(15), to, from, streamID);
        }
        streamID = UUID.randomUUID().toString();
    }

    void processDialback() throws Exception {
        if (checkSID != null) {
            sendDialbackVerify(checkSID, dbKey);
        }
        send("<db:result from='" + from.toEscapedString() + "' to='" + to.toEscapedString() + "'>" +
            dbKey + "</db:result>");
    }

    @Override
    public void handshake() {
        try {
            send("<?xml version='1.0'?><stream:stream xmlns='jabber:server' id='" + streamID +
                "' xmlns:stream='http://etherx.jabber.org/streams' xmlns:db='jabber:server:dialback' from='" +
                from.toEscapedString() + "' to='" + to.toEscapedString() + "' version='1.0'>");

            parser.next(); // stream:stream
            streamID = parser.getAttributeValue(null, "id");
            if (streamID == null || streamID.isEmpty()) {
                throw new Exception("stream to " + to + " invalid first packet");
            }

            logger.info("stream to {} {} open", to, streamID);
            boolean xmppversionnew = parser.getAttributeValue(null, "version") != null;
            if (!xmppversionnew) {
                processDialback();
            }

            while (parser.next() != XmlPullParser.END_DOCUMENT) {
                if (parser.getEventType() != XmlPullParser.START_TAG) {
                    continue;
                }

                String tag = parser.getName();
                if (tag.equals("result") && parser.getNamespace().equals(NS_DB)) {
                    String type = parser.getAttributeValue(null, "type");
                    if (type != null && type.equals("valid")) {
                        streamReady = true;
                        connectionListener.ready(this);
                    } else {
                        logger.info("stream to {} {} dialback fail", to, streamID);
                    }
                    XmlUtils.skip(parser);
                } else if (tag.equals("verify") && parser.getNamespace().equals(NS_DB)) {
                    String from = parser.getAttributeValue(null, "from");
                    String type = parser.getAttributeValue(null, "type");
                    String sid = parser.getAttributeValue(null, "id");
                    connectionListener.verify(this, from, type, sid);
                    XmlUtils.skip(parser);
                } else if (tag.equals("features") && parser.getNamespace().equals(NS_STREAM)) {
                    StreamFeatures features = StreamFeatures.parse(parser);
                    if (connectionListener != null && !secured && features.STARTTLS >= 0 && connectionListener.securing(this)) {
                        logger.info("stream to {} {} securing", to.toEscapedString(), streamID);
                        send("<starttls xmlns=\"" + NS_TLS + "\" />");
                    } else {
                        processDialback();
                    }
                } else if (tag.equals("proceed") && parser.getNamespace().equals(NS_TLS)) {
                    connectionListener.proceed(this);
                } else if (secured && tag.equals("stream") && parser.getNamespace().equals(NS_STREAM)) {
                    streamID = parser.getAttributeValue(null, "id");
                } else if (tag.equals("error")) {
                    StreamError streamError = StreamError.parse(parser);
                    connectionListener.dialbackError(this, streamError);
                } else {
                    String unhandledStanza = XmlUtils.parseToString(parser, true);
                    logger.warn("Unhandled stanza from {} {} : {}", to, streamID, unhandledStanza);
                }
            }
            connectionListener.finished(this, false);
        } catch (EOFException | SocketException eofex) {
            connectionListener.finished(this, true);
        } catch (Exception e) {
            connectionListener.exception(this, e);
        }
    }

    public void sendDialbackVerify(String sid, String key) {
        send("<db:verify from='" + from.toEscapedString() + "' to='" + to + "' id='" + sid + "'>" +
            key + "</db:verify>");
    }

    public void setConnectionListener(ConnectionListener connectionListener) {
        this.connectionListener = connectionListener;
    }

    public String getStreamID() {
        return streamID;
    }

    public boolean isSecured() {
        return secured;
    }

    public void setSecured(boolean secured) {
        this.secured = secured;
    }

    public static String generateKey(String secret, Jid to, Jid from, String id) {
        return HmacUtils.hmacSha256Hex(DigestUtils.sha256(secret),
            (to.toEscapedString() + " " + from.toEscapedString() + " " + id).getBytes());
    }
}
