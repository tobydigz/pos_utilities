package com.tobydigz.nibss_pos_helper.keyexchange.iso8583.ssl_factories

import org.jpos.iso.ISOClientSocketFactory
import org.jpos.iso.ISOException
import java.io.IOException
import java.net.Socket
import javax.net.ssl.SSLSocketFactory

class SecureSSLSocketFactory : ISOClientSocketFactory {
    @Throws(IOException::class, ISOException::class)
    override fun createSocket(s: String, i: Int): Socket {
        val sslsocketfactory = SSLSocketFactory.getDefault() as SSLSocketFactory
        return sslsocketfactory
                .createSocket(s, i)
    }
}
