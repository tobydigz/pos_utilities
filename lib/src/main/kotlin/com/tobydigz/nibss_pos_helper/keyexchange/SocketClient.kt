package com.tobydigz.nibss_pos_helper.keyexchange

import com.tobydigz.nibss_pos_helper.keyexchange.iso8583.NibssChannel
import com.tobydigz.nibss_pos_helper.keyexchange.iso8583.ssl_factories.PlainSocketFactory
import com.tobydigz.nibss_pos_helper.keyexchange.iso8583.ssl_factories.SecureSSLSocketFactory
import org.jpos.iso.BaseChannel
import org.jpos.iso.ISOPackager
import org.jpos.iso.channel.ASCIIChannel
import org.jpos.util.NameRegistrar

object SocketClient {
    enum class ChannelType(name: String) {
        NIBSS("nibss"), ASCII("ascii")
    }


    fun getChannel(packager: ISOPackager, ip: String, port: Int, secure: Boolean, type: ChannelType): BaseChannel {
        val channelName = "${type.name}$ip$port"
        val existingChannel = NameRegistrar.getIfExists<BaseChannel>(channelName)

        if (null !== existingChannel) {
            return existingChannel
        }

        val channel = createPlainChannel(type, ip, port, packager)
        val factory = if (secure) {
            SecureSSLSocketFactory()
        } else {
            PlainSocketFactory()
        }
        channel.socketFactory = factory

        try {
            channel.setTimeout(60000)
        } catch (exception: Exception) {
            exception.printStackTrace()
        }
        channel.setName(channelName)

        NameRegistrar.register(channelName, channel)

        return channel
    }

    fun createPlainChannel(type: ChannelType, ip: String, port: Int, packager: ISOPackager): BaseChannel {
        return when (type) {
            ChannelType.NIBSS -> {
                NibssChannel(ip, port, packager)
            }

            ChannelType.ASCII -> {
                ASCIIChannel(ip, port, packager)
            }
        }
    }
}
