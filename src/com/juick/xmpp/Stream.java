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
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.Socket;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import javax.net.ssl.SSLSocketFactory;
import org.xmlpull.mxp1.MXParser;
import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;

/**
 *
 * @author Ugnich Anton
 */
public abstract class Stream extends Thread {

    public interface StreamListener {

        /**
         * This event is sent when a parser or connection error occurs.
         */
        public void onConnectionFailed(final String msg);

        /**
         * This event occurs when the login/authentication process succeeds.
         */
        public void onAuth(final String resource);

        /**
         * This event occurs when the login/authentication process fails.
         *
         * @param message some error information
         */
        public void onAuthFailed(final String message);
    }
    public JID jid;
    String password;
    String server;
    private int port;
    private boolean use_ssl;
    protected XmlPullParser parser;
    protected OutputStreamWriter writer;
    HashMap<String, StanzaChild> childParsers = new HashMap<String, StanzaChild>();
    ArrayList<StreamListener> listenersXmpp = new ArrayList<StreamListener>();
    ArrayList<Message.MessageListener> listenersMessage = new ArrayList<Message.MessageListener>();
    ArrayList<Presence.PresenceListener> listenersPresence = new ArrayList<Presence.PresenceListener>();
    ArrayList<Iq.IqListener> listenersIq = new ArrayList<Iq.IqListener>();
    HashMap<String, Iq.IqListener> listenersIqId = new HashMap<String, Iq.IqListener>();
    boolean loggedIn;
    Socket connection;

    public boolean openStreams(final String host, int port, boolean use_ssl) {
        try {
            if (!use_ssl) {
                connection = new Socket(host, port);
            } else {
                connection = SSLSocketFactory.getDefault().createSocket(host, port);
            }
            restartParser();
            writer = new OutputStreamWriter(connection.getOutputStream());
        } catch (Exception e) {
            connectionFailed(e.toString());
            return false;
        }
        return true;
    }

    public void restartParser() throws XmlPullParserException, IOException {
        parser = new MXParser();
        parser.setInput(new InputStreamReader(connection.getInputStream()));
        parser.setFeature(XmlPullParser.FEATURE_PROCESS_NAMESPACES, true);
    }

    public Stream(final JID jid, final String password, final String server, final int port, final boolean use_ssl) {
        this.jid = jid;
        this.password = password;
        if (server == null || server.length() == 0) {
            this.server = jid.Host;
        } else {
            this.server = server;
        }
        this.port = port;
        this.use_ssl = use_ssl;
        loggedIn = false;
    }

    @Override
    public void run() {
        if (!openStreams(server, port, use_ssl)) {
            return;
        }

        // connected
        try {
            login();
            parse();
        } catch (final Exception e) {
            connectionFailed(e.toString());
        }
    }

    public void addChildParser(StanzaChild childparser) {
        childParsers.put(childparser.getXMLNS(), childparser);
    }

    public void removeChildParser(final String xmlns) {
        childParsers.remove(xmlns);
    }

    public void addListener(final StreamListener l) {
        if (!listenersXmpp.contains(l)) {
            listenersXmpp.add(l);
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
        return listenersXmpp.remove(l);
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

    public abstract void login() throws XmlPullParserException, IOException;

    public void logoff() {
        loggedIn = false;
        try {
            writer.flush();
            writer.close();
            //TODO close parser
        } catch (final Exception e) {
            connectionFailed(e.toString());
        }
    }

    public void send(final Stanza s) {
        try {
            writer.write(s.toString());
            writer.flush();
        } catch (final Exception e) {
            connectionFailed(e.toString());
        }
    }

    private void parse() throws XmlPullParserException, IOException {
        while (parser.next() == XmlPullParser.START_TAG) {
            final String tag = parser.getName();
            if (tag.equals("message")) {
                Message msg = Message.parse(parser, childParsers);
                for (Iterator<Message.MessageListener> it = listenersMessage.iterator(); it.hasNext();) {
                    it.next().onMessage(msg);
                }
            } else if (tag.equals("presence")) {
                Presence p = Presence.parse(parser, childParsers);
                for (Iterator<Presence.PresenceListener> it = listenersPresence.iterator(); it.hasNext();) {
                    it.next().onPresence(p);
                }
            } else if (tag.equals("iq")) {
                Iq iq = Iq.parse(parser, childParsers);
                if (iq.from == null) {
                    iq.from = new JID(this.jid.Host);
                }
                final String key = iq.from.toString() + "\n" + iq.id;
                boolean parsed = false;
                if (listenersIqId.containsKey(key)) {
                    Iq.IqListener l = (Iq.IqListener) listenersIqId.get(key);
                    parsed |= l.onIq(iq);
                    listenersIqId.remove(key);
                } else {
                    for (Iterator<Iq.IqListener> it = listenersIq.iterator(); it.hasNext();) {
                        parsed |= it.next().onIq(iq);
                    }
                }
                if (!parsed) {
                    send(iq.error());
                }
            } else {
                XmlUtils.skip(parser);
            }
        }
        XmlUtils.skip(parser);
    }

    /**
     * This method is used to be called on a parser or a connection error.
     * It tries to close the XML-Reader and XML-Writer one last time.
     */
    protected void connectionFailed(final String msg) {
        if (loggedIn) {
            try {
                writer.close();
                //TODO close parser
            } catch (Exception e) {
            }
        }

        for (Iterator<StreamListener> it = listenersXmpp.iterator(); it.hasNext();) {
            it.next().onConnectionFailed(msg);
        }
    }
}