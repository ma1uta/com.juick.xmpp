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

import java.util.Enumeration;
import java.util.Vector;
import org.xmlpull.v1.XmlPullParser;

/**
 *
 * @author Ugnich Anton
 */
public class Stanza {

    public JID from = null;
    public JID to = null;
    public String id = Long.toString(System.currentTimeMillis());
    public String type = null;
    public Vector childs = new Vector();

    public void addChild(StanzaChild child) {
        childs.addElement(child);
    }

    public boolean hasChilds() {
        return !childs.isEmpty();
    }

    public StanzaChild getChild(String XMLNS) {
        for (Enumeration e = childs.elements(); e.hasMoreElements();) {
            StanzaChild ce = (StanzaChild) e.nextElement();
            if (ce.getXMLNS().equals(XMLNS)) {
                return ce;
            }
        }
        return null;
    }

    public void parseStanza(XmlPullParser parser) {
        final String fromStr = parser.getAttributeValue(null, "from");
        if (fromStr != null) {
            from = new JID(fromStr);
        }

        final String toStr = parser.getAttributeValue(null, "to");
        if (toStr != null) {
            to = new JID(toStr);
        }

        id = parser.getAttributeValue(null, "id");
        type = parser.getAttributeValue(null, "type");
    }

    @Override
    public String toString() {
        String str = new String();
        if (from != null) {
            str += " from='" + from.toString() + "'";
        }
        if (to != null) {
            str += " to='" + to.toString() + "'";
        }
        if (id != null) {
            str += " id='" + XmlUtils.escape(id) + "'";
        }
        if (type != null) {
            str += " type='" + XmlUtils.escape(type) + "'";
        }
        return str;
    }
}
