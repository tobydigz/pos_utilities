package com.tobydigz.nibss_pos_helper.keyexchange.iso8583;

import com.tobydigz.nibss_pos_helper.keyexchange.iso8583.ssl_factories.InsecureSSLSocketFactory;
import com.tobydigz.nibss_pos_helper.keyexchange.iso8583.ssl_factories.SecureSSLSocketFactory;
import org.jpos.iso.BaseChannel;
import org.jpos.iso.ISOClientSocketFactory;
import org.jpos.iso.ISOPackager;

import java.io.IOException;
import java.net.SocketException;
import java.util.Objects;
import java.util.concurrent.TimeoutException;

/*
 * This Channel can be used to connect to Nibss like ISO-Servers.
 * It's a custom impl of a channel.
 * */
public class NibssChannelBackup extends BaseChannel {

    public NibssChannelBackup(String host, int port, ISOPackager p) {
        super(host, port, p);

        /*
        * Flag to determine if we use secure ssl or a factory that accepts all certificates
        * */
        boolean secure = Objects.equals(System.getenv("CONNECTION_MODE_SECURE"), "secure");

        ISOClientSocketFactory factory;
        if (secure){
            factory = new SecureSSLSocketFactory();
        } else {
            factory = new InsecureSSLSocketFactory();
        }
        setSocketFactory(factory);
        setTimeOut();
    }

    /**
     * Determines the length of the message that is being se
     *
     * @param len the packed Message len
     * @throws IOException
     */
    @Override
    protected void sendMessageLength(int len) throws IOException {
        // NIBSS expects header length to be 2 byte length header field in
        // binary
        System.out.println("The value being sent  is " + len + " and "
                + (len >> 8));
        serverOut.write((len >> 8) & 0xff);
        serverOut.write(len & 0xff);

    }

    @Override
    protected int getHeaderLength() {
        return 0;
    }

    /*Set time out*/
    private void setTimeOut() {
        try {
            super.setTimeout(60000);
        } catch (SocketException e) {
            try {
                throw new TimeoutException("Transaction timed out!");
            } catch (TimeoutException e1) {
                e1.printStackTrace();
            }
        }
    }

    /**
     * @return the Message len
     * @throws IOException , ISOException
     */
    @Override
    protected int getMessageLength() throws IOException {
        int l = 0;
        byte[] b = new byte[2];
        while (l == 0) {
            serverIn.readFully(b, 0, 2);
            l = ((b[0] & 0xFF) << 8) | (b[1] & 0xFF);
            if (l == 0) {
                serverOut.write(b);

            }
            serverOut.flush();
        }
        return l;

    }
}
