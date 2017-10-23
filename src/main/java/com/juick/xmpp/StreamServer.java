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

import static com.juick.xmpp.StreamServerDialback.NS_DB;
import static com.juick.xmpp.StreamServerDialback.NS_TLS;

import com.juick.xmpp.utils.XmlUtils;
import lombok.Getter;
import lombok.Setter;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;
import rocks.xmpp.addr.Jid;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.SocketException;
import java.text.ParseException;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * @author ugnich
 */
@Getter
public class StreamServer extends Stream {

    public static final String NS_SERVER = "jabber:server";

    private static final Logger LOGGER = LoggerFactory.getLogger(StreamServer.class);

    private List<Jid> fromJids = new CopyOnWriteArrayList<>();
    private Instant received;
    @Setter
    private ConnectionListener listener;
    private String streamID;
    private boolean secured = false;
    @Setter
    private String[] brokenSSLhosts;
    @Setter
    private String[] bannedHosts;
    private long packetsRemote = 0;

    public StreamServer(Jid from, Jid to, InputStream is, OutputStream os)
        throws XmlPullParserException {
        super(from, to, is, os);
    }

    @Override
    protected void parse() throws IOException, ParseException {
        try {

            while (parser.next() != XmlPullParser.END_DOCUMENT) {
                updateTsRemoteData();
                if (parser.getEventType() != XmlPullParser.START_TAG) {
                    continue;
                }
                logParser();

                packetsRemote++;

                String tag = parser.getName();
                if (tag.equals("result") && parser.getNamespace().equals(NS_DB)) {
                    String dfrom = parser.getAttributeValue(null, "from");
                    String to = parser.getAttributeValue(null, "to");
                    LOGGER.info("stream from {} to {} {} asking for dialback", dfrom, to, streamID);
                    if (dfrom.endsWith(from.toEscapedString()) && (dfrom.equals(from.toEscapedString())
                        || dfrom.endsWith("." + from))) {
                        LOGGER.warn("stream from {} is invalid", dfrom);
                        break;
                    }
                    if (to != null && to.equals(from.toEscapedString())) {
                        String dbKey = XmlUtils.getTagText(parser);
                        updateTsRemoteData();
                        //xmpp.startDialback(Jid.of(dfrom), streamID, dbKey);
                    } else {
                        LOGGER.warn("stream from " + dfrom + " " + streamID + " invalid to " + to);
                        break;
                    }
                } else if (tag.equals("verify") && parser.getNamespace().equals(NS_DB)) {
                    String vfrom = parser.getAttributeValue(null, "from");
                    String vto = parser.getAttributeValue(null, "to");
                    String vid = parser.getAttributeValue(null, "id");
                    String vkey = XmlUtils.getTagText(parser);
                    updateTsRemoteData();
                    final boolean[] valid = {false};
                    if (vfrom != null && vto != null && vid != null && vkey != null) {
//                        xmpp.getConnectionOut(Jid.of(vfrom), false).ifPresent(c -> {
//                            String dialbackKey = c.dbKey;
//                            valid[0] = vkey.equals(dialbackKey);
//                        });
                    }
                    if (valid[0]) {
                        send("<db:verify from='" + vto + "' to='" + vfrom + "' id='" + vid + "' type='valid'/>");
                        LOGGER.info("stream from {} {} dialback verify valid", vfrom, streamID);
                    } else {
                        send("<db:verify from='" + vto + "' to='" + vfrom + "' id='" + vid + "' type='invalid'/>");
                        LOGGER.warn("stream from {} {} dialback verify invalid", vfrom, streamID);
                    }
                } else if (tag.equals("presence") && checkFromTo(parser)) {
                    presence();
                } else if (tag.equals("message") && checkFromTo(parser)) {
                    message();
                } else if (tag.equals("iq") && checkFromTo(parser)) {
                    updateTsRemoteData();
                    iq();
                } else if (!isSecured() && tag.equals("starttls")) {
                    listener.starttls(this);
                } else if (isSecured() && tag.equals("stream") && parser.getNamespace().equals(NS_STREAM)) {
                    sendOpenStream(null, true);
                } else if (tag.equals("error")) {
                    error();
                    close();
                } else {
                    String unhandledStanza = XmlUtils.parseToString(parser, true);
                    LOGGER.warn("Unhandled stanza from {}: {}", streamID, unhandledStanza);
                }
            }
            LOGGER.warn("stream {} finished", streamID);
//            xmpp.removeConnectionIn(this);
            close();
        } catch (EOFException | SocketException ex) {
            LOGGER.info("stream {} closed (dirty)", streamID);
//            xmpp.removeConnectionIn(this);
            close();
        } catch (Exception e) {
            LOGGER.warn("stream {} error {}", streamID, e);
//            xmpp.removeConnectionIn(this);
            close();
        }
    }

    @Override
    protected void handshake() throws XmlPullParserException, IOException {
        parser.next(); // stream:stream
        updateTsRemoteData();
        if (!parser.getName().equals("stream")
            || !parser.getNamespace("stream").equals(NS_STREAM)) {
//                    || !parser.getAttributeValue(null, "version").equals("1.0")
//                    || !parser.getAttributeValue(null, "to").equals(Main.HOSTNAME)) {
            connectionFailed(new Exception(String.format("stream from %s invalid", from.toEscapedString())));
        }
        streamID = parser.getAttributeValue(null, "id");
        if (streamID == null) {
            streamID = UUID.randomUUID().toString();
        }
        boolean xmppversionnew = parser.getAttributeValue(null, "version") != null;
        String fromJid = parser.getAttributeValue(null, "from");

        if (Arrays.asList(getBannedHosts()).contains(fromJid)) {
            close();
            return;
        }

        sendOpenStream(fromJid, xmppversionnew);

    }

    private void sendOpenStream(String fromJid, boolean xmppversionnew) {
        StringBuilder openStream = new StringBuilder(
            String.format("<?xml version='1.0'?><stream:stream xmlns='%s' xmlns:stream='%s' xmlns:db='%s' from='%s' id='%s' version='1.0'>",
                NS_SERVER, NS_STREAM, NS_DB, from.toEscapedString(), streamID));
        if (xmppversionnew) {
            openStream.append("<stream:features>");
            if (listener != null && !isSecured() && !Arrays.asList(getBrokenSSLhosts()).contains(fromJid)) {
                openStream.append("<starttls xmlns=\"").append(NS_TLS).append("\"><optional/></starttls>");
            }
            openStream.append("</stream:features>");
        }
        send(openStream.toString());
    }

    private void updateTsRemoteData() {
        received = Instant.now();
    }

    public void logParser() {
        if (streamID == null) {
            return;
        }
        StringBuilder tag = new StringBuilder("IN: <").append(parser.getName());
        for (int i = 0; i < parser.getAttributeCount(); i++) {
            tag.append(" ").append(parser.getAttributeName(i)).append("=\"").append(parser.getAttributeValue(i)).append("\"");
        }
        tag.append(">...</").append(parser.getName()).append(">\n");
        LOGGER.trace(tag.toString());
    }

    public void sendDialbackResult(Jid sfrom, String type) {
        send("<db:result from='" + from.toEscapedString() + "' to='" + sfrom + "' type='" + type + "'/>");
        if (type.equals("valid")) {
            getFromJids().add(sfrom);
            LOGGER.info("stream from {} {} ready", sfrom, streamID);
        }
    }

    private boolean checkFromTo(XmlPullParser parser) throws Exception {
        String cfrom = parser.getAttributeValue(null, "from");
        String cto = parser.getAttributeValue(null, "to");
        if (StringUtils.isNotEmpty(cfrom) && StringUtils.isNotEmpty(cto)) {
            Jid jidto = Jid.of(cto);
            if (jidto.getDomain().equals(from.toEscapedString())) {
                Jid jidfrom = Jid.of(cfrom);
                for (Jid aFrom : getFromJids()) {
                    if (aFrom.equals(Jid.of(jidfrom.getDomain()))) {
                        return true;
                    }
                }
            }
        }
        return false;
    }
}
