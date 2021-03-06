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

import com.juick.xmpp.utils.XmlUtils;
import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;
import rocks.xmpp.addr.Jid;

import java.text.ParseException;
import java.util.Map;

/**
 *
 * @author Ugnich Anton
 */
public class Iq extends Stanza {

    public interface IqListener {

        boolean onIq(final Iq iq);
    }

    public static final class Type {

        public static final String get = "get";
        public static final String set = "set";
        public static final String result = "result";
        public static final String error = "error";
    }
    public final static String TagName = "iq";

    public Iq() {
    }

    public Iq(Jid from, Jid to) {
        super(from, to);
    }

    public Iq(Jid from, Jid to, String type) {
        super(from, to, type);
    }

    @Override
    public void addChild(StanzaChild child) {
        childs.clear();
        childs.add(child);
    }

    public StanzaChild getChild() {
        return childs.isEmpty() ? null : childs.get(0);
    }

    public Iq reply() {
        Iq reply = new Iq();
        reply.from = to;
        reply.to = from;
        reply.id = this.id;
        reply.type = Type.result;
        return reply;
    }

    public Iq error() {
        // TODO: implement other types
        Iq error = new Iq();
        error.from = to;
        error.to = from;
        error.id = this.id;
        error.type = Type.error;
        return error;
    }

    public static Iq parse(XmlPullParser parser, Map<String, StanzaChild> childParsers) throws XmlPullParserException, java.io.IOException, ParseException {
        Iq iq = new Iq();
        iq.parseStanza(parser);

        String currentTag = parser.getName();
        while (!(parser.next() == XmlPullParser.END_TAG && parser.getName().equals(currentTag))) {
            if (parser.getEventType() == XmlPullParser.START_TAG) {
                final String xmlns = parser.getNamespace();
                if (xmlns != null && childParsers != null) {
                    StanzaChild childparser = childParsers.get(xmlns);
                    if (childparser != null) {
                        StanzaChild child = childparser.parse(parser);
                        if (child != null) {
                            iq.addChild(child);
                        } else {
                            XmlUtils.skip(parser);
                        }
                    } else {
                        XmlUtils.skip(parser);
                    }
                } else {
                    XmlUtils.skip(parser);
                }
            }
        }
        return iq;
    }

    @Override
    public String toString() {
        StringBuilder str = new StringBuilder("<").append(TagName).append(super.toString()).append(">");
        for (StanzaChild child : childs) {
            str.append(child.toString());
        }
        if (type.equals(Type.error)) {
            str.append("<error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' /></error>");
        }
        str.append("</").append(TagName).append(">");
        return str.toString();
    }
}
