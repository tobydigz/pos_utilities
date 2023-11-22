package com.tobydigz.nibss_pos_helper.keyexchange.iso8583.ssl_factories

import org.jpos.iso.ISOClientSocketFactory
import org.jpos.iso.ISOException
import java.io.IOException
import java.net.Socket
import javax.net.SocketFactory

class PlainSocketFactory : ISOClientSocketFactory {
    @Throws(IOException::class, ISOException::class)
    override fun createSocket(host: String, port: Int): Socket {
        return SocketFactory.getDefault().createSocket(host, port)
    }
}
