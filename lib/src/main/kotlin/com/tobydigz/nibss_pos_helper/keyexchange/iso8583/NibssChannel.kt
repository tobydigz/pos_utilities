package com.tobydigz.nibss_pos_helper.keyexchange.iso8583

import com.tobydigz.nibss_pos_helper.keyexchange.iso8583.ssl_factories.InsecureSSLSocketFactory
import com.tobydigz.nibss_pos_helper.keyexchange.iso8583.ssl_factories.SecureSSLSocketFactory
import org.jpos.iso.BaseChannel
import org.jpos.iso.ISOClientSocketFactory
import org.jpos.iso.ISOPackager
import java.io.IOException
import java.net.SocketException
import java.util.concurrent.TimeoutException

/*
* This Channel can be used to connect to Nibss like ISO-Servers.
* It's a custom impl of a channel.
* */
class NibssChannel(host: String?, port: Int, p: ISOPackager?) : BaseChannel(host, port, p) {
    init {

        /*
        * Flag to determine if we use secure ssl or a factory that accepts all certificates
        * */
        val secure = System.getenv("CONNECTION_MODE_SECURE") == "secure"
        val factory: ISOClientSocketFactory
        factory = if (secure) {
            SecureSSLSocketFactory()
        } else {
            InsecureSSLSocketFactory()
        }
        setSocketFactory(factory)
        setTimeOut()
    }

    /**
     * Determines the length of the message that is being se
     *
     * @param len the packed Message len
     * @throws IOException
     */
    @Throws(IOException::class)
    override fun sendMessageLength(len: Int) {
        // NIBSS expects header length to be 2 byte length header field in
        // binary
        println("The value being sent  is " + len + " and "
                + (len shr 8))
        serverOut.write(len shr 8 and 0xff)
        serverOut.write(len and 0xff)
    }

    override fun getHeaderLength(): Int {
        return 0
    }

    /*Set time out*/
    private fun setTimeOut() {
        try {
            super.setTimeout(60000)
        } catch (e: SocketException) {
            try {
                throw TimeoutException("Transaction timed out!")
            } catch (e1: TimeoutException) {
                e1.printStackTrace()
            }
        }
    }

    /**
     * @return the Message len
     * @throws IOException , ISOException
     */
    @Throws(IOException::class)
    override fun getMessageLength(): Int {
        var l = 0
        val b = ByteArray(2)
        while (l == 0) {
            serverIn.readFully(b, 0, 2)
            l = b[0].toInt() and 0xFF shl 8 or (b[1].toInt() and 0xFF)
            if (l == 0) {
                serverOut.write(b)
            }
            serverOut.flush()
        }
        return l
    }
}
