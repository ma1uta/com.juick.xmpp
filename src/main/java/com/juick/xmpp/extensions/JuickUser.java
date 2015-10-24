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
package com.juick.xmpp.extensions;

import com.juick.xmpp.utils.XmlUtils;
import com.juick.xmpp.*;
import java.io.IOException;
import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;

/**
 *
 * @author Ugnich Anton
 */
public class JuickUser extends com.juick.User implements StanzaChild {

    public final static String XMLNS = "http://juick.com/user";
    public final static String TagName = "user";

    public JuickUser() {
    }

    public JuickUser(com.juick.User user) {
        super(user);
    }

    @Override
    public String getXMLNS() {
        return XMLNS;
    }

    @Override
    public JuickUser parse(final XmlPullParser parser) throws XmlPullParserException, IOException {
        JuickUser juser = new JuickUser();
        String strUID = parser.getAttributeValue(null, "uid");
        if (strUID != null) {
            juser.UID = Integer.parseInt(strUID);
        }
        juser.UName = parser.getAttributeValue(null, "uname");
        XmlUtils.skip(parser);
        return juser;
    }

    public static String toString(com.juick.User user) {
        String str = "<" + TagName + " xmlns='" + XMLNS + "'";
        if (user.UID > 0) {
            str += " uid='" + user.UID + "'";
        }
        if (user.UName != null && user.UName.length() > 0) {
            str += " uname='" + XmlUtils.escape(user.UName) + "'";
        }
        str += "/>";
        return str;
    }

    @Override
    public String toString() {
        return toString(this);
    }
}