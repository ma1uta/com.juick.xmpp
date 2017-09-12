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
package com.juick.xmpp.utils;

import java.io.IOException;
import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;

/**
 *
 * @author Ugnich Anton
 */
public class XmlUtils {

    public static void skip(XmlPullParser parser) throws XmlPullParserException, IOException {
        String tag = parser.getName();
        while (parser.getName() != null && !(parser.next() == XmlPullParser.END_TAG && parser.getName().equals(tag))) {
        }
    }

    public static String getTagText(XmlPullParser parser) throws XmlPullParserException, IOException {
        String ret = "";
        String tag = parser.getName();

        if (parser.next() == XmlPullParser.TEXT) {
            ret = parser.getText();
        }

        while (!(parser.getEventType() == XmlPullParser.END_TAG && parser.getName().equals(tag))) {
            parser.next();
        }

        return ret;
    }

    public static String parseToString(XmlPullParser parser, boolean skipXMLNS) throws XmlPullParserException, IOException {
        String tag = parser.getName();
        String ret = "<" + tag;

        // skipXMLNS for xmlns="jabber:client"

        String ns = parser.getNamespace();
        if (!skipXMLNS && ns != null && !ns.isEmpty()) {
            ret += " xmlns=\"" + ns + "\"";
        }

        for (int i = 0; i < parser.getAttributeCount(); i++) {
            String attr = parser.getAttributeName(i);
            if ((!skipXMLNS || !attr.equals("xmlns")) && !attr.contains(":")) {
                ret += " " + attr + "=\"" + escape(parser.getAttributeValue(i)) + "\"";
            }
        }
        ret += ">";

        while (!(parser.next() == XmlPullParser.END_TAG && parser.getName().equals(tag))) {
            int event = parser.getEventType();
            if (event == XmlPullParser.START_TAG) {
                if (!parser.getName().contains(":")) {
                    ret += parseToString(parser, false);
                } else {
                    skip(parser);
                }
            } else if (event == XmlPullParser.TEXT) {
                ret += escape(parser.getText());
            }
        }

        ret += "</" + tag + ">";
        return ret;
    }

    public static String escape(String str) {
        String res = "";
        for (int i = 0; i < str.length(); i++) {
            final char c = str.charAt(i);
            switch (c) {
                case '<':
                    res += "&lt;";
                    break;
                case '>':
                    res += "&gt;";
                    break;
                case '&':
                    res += "&amp;";
                    break;
                case '\'':
                    res += "&apos;";
                    break;
                case '"':
                    res += "&quot;";
                    break;
                default:
                    res += c;
            }
        }
        return res;
    }
}
