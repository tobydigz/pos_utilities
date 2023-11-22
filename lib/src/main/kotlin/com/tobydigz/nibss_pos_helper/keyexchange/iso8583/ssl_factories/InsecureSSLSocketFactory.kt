package com.tobydigz.nibss_pos_helper.keyexchange.iso8583.ssl_factories

import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.jpos.iso.ISOClientSocketFactory
import org.jpos.iso.ISOException
import java.io.IOException
import java.net.Socket
import java.security.SecureRandom
import java.security.Security
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

class InsecureSSLSocketFactory : ISOClientSocketFactory {
    @Throws(IOException::class, ISOException::class)
    override fun createSocket(host: String, port: Int): Socket? {
        Security.addProvider(BouncyCastleProvider())
        val factory = createSocketFactory() ?: return null
        return factory.createSocket(host, port)
    }

    private fun createSocketFactory(): SSLSocketFactory? {
        val context = sSLContext
        return context?.socketFactory
    }

    private val sSLContext: SSLContext?
        private get() {
            Security.addProvider(BouncyCastleProvider())
            try {
                val tma = trustManagers
                val sslContext = SSLContext.getInstance("TLS")
                sslContext.init(null, tma, SecureRandom.getInstance("SHA1PRNG"))
                return sslContext
            } catch (e: Exception) {
                e.printStackTrace()
            }
            return null
        }
    private val trustManagers: Array<TrustManager>
        private get() = arrayOf(object : X509TrustManager {
            @Throws(CertificateException::class)
            override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {
            }

            @Throws(CertificateException::class)
            override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
            }

            override fun getAcceptedIssuers(): Array<X509Certificate> {
                return arrayOf()
            }
        })
}
