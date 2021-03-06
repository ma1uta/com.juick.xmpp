/*
 * Juick
 * Copyright (C) 2008-2011, Ugnich Anton
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

import org.apache.commons.codec.digest.DigestUtils;
import org.xmlpull.v1.XmlPullParserException;
import rocks.xmpp.addr.Jid;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * @author Ugnich Anton
 */
public class StreamComponent extends Stream {

    public static final String NS_COMPONENT_ACCEPT = "jabber:component:accept";

    private String password;

    public StreamComponent(Jid to, InputStream is, OutputStream os, String password) throws XmlPullParserException {
        super(null, to, is, os);
        this.password = password;
    }

    @Override
    public void handshake() throws XmlPullParserException, IOException {
        send(String.format("<stream:stream xmlns='%s' xmlns:stream='%s' to='%s'>", NS_COMPONENT_ACCEPT, NS_STREAM, to.toEscapedString()));

        parser.next(); // stream:stream
        String sid = parser.getAttributeValue(null, "id");
        String sfrom = parser.getAttributeValue(null, "from");
        if (sfrom == null || !sfrom.equals(to.toString())) {
            setLoggedIn(false);
            getListenersStream().forEach(listener -> listener.fail(new IOException("stream:stream, failed authentication")));
            return;
        }

        send("<handshake>" + DigestUtils.sha1Hex(sid + password) + "</handshake>");

        parser.next();
        if (parser.getName().equals("handshake")) {
            parser.next();
            setLoggedIn(true);
            listenersStream.forEach(StreamListener::ready);
        } else {
            setLoggedIn(false);
            for (StreamListener listener : listenersStream) {
                listener.fail(new IOException(String.format("%s, failed authentication", parser.getName())));
            }
        }
    }
}
