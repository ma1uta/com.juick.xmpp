package com.juick.xmpp;

import com.juick.xmpp.extensions.StreamError;

public interface ConnectionListener {
    void starttls(StreamServer connection);

    void proceed(StreamServerDialback connection);

    void verify(StreamServerDialback connection, String from, String type, String sid);

    void dialbackError(StreamServerDialback connection, StreamError error);

    void finished(StreamServerDialback connection, boolean dirty);

    void exception(StreamServerDialback connection, Exception ex);

    void ready(StreamServerDialback connection);

    boolean securing(StreamServerDialback connection);
}
