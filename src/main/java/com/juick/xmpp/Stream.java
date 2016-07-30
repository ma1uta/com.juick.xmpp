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
import org.xmlpull.mxp1.MXParser;
import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;

import java.io.*;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 *
 * @author Ugnich Anton
 */
public abstract class Stream {

    public boolean isLoggedIn() {
        return loggedIn;
    }

    public void setLoggedIn(boolean loggedIn) {
        this.loggedIn = loggedIn;
    }

    public interface StreamListener {

        void onStreamReady();

        void onStreamFail(final Exception ex);
    }
    public JID from;
    public JID to;
    protected InputStream is;
    protected XmlPullParser parser;
    protected OutputStreamWriter writer;
    Map<String, StanzaChild> childParsers = new HashMap<>();
    List<StreamListener> listenersStream = new ArrayList<>();
    List<Message.MessageListener> listenersMessage = new ArrayList<>();
    List<Presence.PresenceListener> listenersPresence = new ArrayList<>();
    List<Iq.IqListener> listenersIq = new ArrayList<>();
    HashMap<String, Iq.IqListener> listenersIqId = new HashMap<>();
    private boolean loggedIn;

    public Stream(final JID from, final JID to, final InputStream is, final OutputStream os) {
        this.from = from;
        this.to = to;
        this.is = is;
        writer = new OutputStreamWriter(os);
    }

    public void restartParser() throws XmlPullParserException, IOException {
        parser = new MXParser();
        parser.setInput(new InputStreamReader(is));
        parser.setFeature(XmlPullParser.FEATURE_PROCESS_NAMESPACES, true);
    }

    public void startParsing() {
        try {
            restartParser();
            openStream();
            parse();
        } catch (final Exception e) {
            connectionFailed(e);
        }
    }

    public void addChildParser(StanzaChild childparser) {
        childParsers.put(childparser.getXMLNS(), childparser);
    }

    public void removeChildParser(final String xmlns) {
        childParsers.remove(xmlns);
    }

    public void addListener(final StreamListener l) {
        if (!listenersStream.contains(l)) {
            listenersStream.add(l);
        }
    }

    public void addListener(final Message.MessageListener l) {
        if (!listenersMessage.contains(l)) {
            listenersMessage.add(l);
        }
    }

    public void addListener(final Presence.PresenceListener l) {
        if (!listenersPresence.contains(l)) {
            listenersPresence.add(l);
        }
    }

    public void addListener(final Iq.IqListener l) {
        if (!listenersIq.contains(l)) {
            listenersIq.add(l);
        }
    }

    public void addListener(final String jid, final String id, final Iq.IqListener iql) {
        listenersIqId.put(jid + "\n" + id, iql);
    }

    public boolean removeListener(final StreamListener l) {
        return listenersStream.remove(l);
    }

    public boolean removeListener(final Message.MessageListener l) {
        return listenersMessage.remove(l);
    }

    public boolean removeListener(final Presence.PresenceListener l) {
        return listenersPresence.remove(l);
    }

    public boolean removeListener(final Iq.IqListener l) {
        return listenersIq.remove(l);
    }

    public abstract void openStream() throws XmlPullParserException, IOException;

    public void logoff() {
        setLoggedIn(false);
        try {
            writer.flush();
            writer.close();
            //TODO close parser
        } catch (final Exception e) {
            connectionFailed(e);
        }
    }

    public void send(final Stanza s) {
        send(s.toString());
    }

    public void send(final String str) {
        try {
            writer.write(str);
            writer.flush();
        } catch (final Exception e) {
            connectionFailed(e);
        }
    }

    private void parse() throws XmlPullParserException, IOException, ParseException {
        while (parser.next() == XmlPullParser.START_TAG) {
            final String tag = parser.getName();
            switch (tag) {
                case "message":
                    Message msg = Message.parse(parser, childParsers);
                    for (Message.MessageListener listener : listenersMessage) {
                        listener.onMessage(msg);
                    }
                    break;
                case "presence":
                    Presence p = Presence.parse(parser, childParsers);
                    for (Presence.PresenceListener listener : listenersPresence) {
                        listener.onPresence(p);
                    }
                    break;
                case "iq":
                    Iq iq = Iq.parse(parser, childParsers);
                    final String key = (iq.from == null) ? "" : iq.from.toString() + "\n" + iq.id;
                    boolean parsed = false;
                    if (listenersIqId.containsKey(key)) {
                        Iq.IqListener l = listenersIqId.get(key);
                        parsed = l.onIq(iq);
                        listenersIqId.remove(key);
                    } else {
                        for (Iq.IqListener listener : listenersIq) {
                            parsed |= listener.onIq(iq);
                        }
                    }
                    if (!parsed) {
                        send(iq.error());
                    }
                    break;
                default:
                    XmlUtils.skip(parser);
                    break;
            }
        }
        XmlUtils.skip(parser);
    }

    /**
     * This method is used to be called on a parser or a connection error.
     * It tries to close the XML-Reader and XML-Writer one last time.
     */
    protected void connectionFailed(final Exception ex) {
        if (isLoggedIn()) {
            try {
                writer.close();
                //TODO close parser
            } catch (Exception e) {
            }
        }

        for (StreamListener listener : listenersStream) {
            listener.onStreamFail(ex);
        }
    }
}
