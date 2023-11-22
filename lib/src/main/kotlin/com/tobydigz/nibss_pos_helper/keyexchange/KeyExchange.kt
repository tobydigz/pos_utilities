package com.tobydigz.nibss_pos_helper.keyexchange

import com.tobydigz.nibss_pos_helper.Utils.generateStan
import com.tobydigz.nibss_pos_helper.Utils.performSHA256Hash
import com.tobydigz.nibss_pos_helper.keyexchange.iso8583.Packager
import org.jpos.iso.*
import java.io.IOException
import java.security.InvalidKeyException
import java.security.NoSuchAlgorithmException
import java.security.NoSuchProviderException
import java.util.*
import javax.crypto.BadPaddingException
import javax.crypto.IllegalBlockSizeException
import javax.crypto.NoSuchPaddingException

class KeyExchange(private val terminalId: String, private val channel: BaseChannel, private val packager: Packager, private val keyManager: KeyManager) {
    private val emptyMap = emptyMap<Int, String>()

    @Throws(IOException::class, ISOException::class, NoSuchPaddingException::class, NoSuchAlgorithmException::class, IllegalBlockSizeException::class, BadPaddingException::class, NoSuchProviderException::class, InvalidKeyException::class)
    fun runTMK(): String {
        val resp = sendMessage(processingCode = "9A0000", terminalId = terminalId, map = emptyMap, calculateHash = Pair(false, 0))

        val result = resp.getString(39)

        if (result.endsWith("00")) {  // check if 39 equals 00
            keyManager.setEncryptedMasterKey(resp.getString(53))
        }
        return result
    }

    @Throws(IOException::class, ISOException::class, NoSuchPaddingException::class, NoSuchAlgorithmException::class, IllegalBlockSizeException::class, BadPaddingException::class, NoSuchProviderException::class, InvalidKeyException::class)
    fun runTSK(): String {
        val resp = sendMessage(processingCode = "9B0000", terminalId = terminalId, map = emptyMap, calculateHash = Pair(false, 0))

        val result = resp.getString(39)

        if (result.endsWith("00")) {  // check if 39 equals 00
            keyManager.setEncryptedSessionKey(resp.getString(53))
        }
        return result
    }

    @Throws(IOException::class, ISOException::class)
    fun runTPK(): String {
        val resp = sendMessage(processingCode = "9G0000", terminalId = terminalId, map = emptyMap, calculateHash = Pair(false, 0))

        return resp.getString(39)
    }

    @Throws(IOException::class, ISOException::class, NoSuchAlgorithmException::class)
    fun runParamDownload(): String {
        val map = mapOf(Pair(62, "01008$terminalId"))
        val resp = sendMessage(processingCode = "9C0000", terminalId = terminalId, map = map, calculateHash = Pair(true, 64))

        return resp.getString(39)
    }

    @Throws(IOException::class, ISOException::class, NoSuchAlgorithmException::class)
    fun runCAPKDownload(): String {
        val map = mapOf(Pair(63, "01008$terminalId"))
        val resp = sendMessage(processingCode = "9E0000", terminalId = terminalId, map = map, calculateHash = Pair(true, 64))

        return resp.getString(39)
    }

    @Throws(IOException::class, ISOException::class, NoSuchAlgorithmException::class)
    fun runAIDDownload(): String {
        val map = mapOf(Pair(63, "01008$terminalId"))
        val resp = sendMessage(processingCode = "9F0000", terminalId = terminalId, map = map, calculateHash = Pair(true, 64))

        return resp.getString(39)
    }


    private fun sendMessage(mti: String = "0800", processingCode: String, terminalId: String, map: Map<Int, String>, calculateHash: Pair<Boolean, Int>): ISOMsg {
        val transactionDate = Date()
        val transDate = ISODate.getDate(transactionDate, TimeZone.getTimeZone("GMT+1"))
        val transTime = ISODate.getTime(transactionDate, TimeZone.getTimeZone("GMT+1"))
        val transDateTime = ISODate.getDateTime(transactionDate, TimeZone.getTimeZone("GMT+1"))
        channel.connect()
        val isoMsg = ISOMsg()
        isoMsg.packager = packager
        isoMsg.mti = mti
        isoMsg[3] = processingCode
        isoMsg[7] = transDateTime
        isoMsg[11] = generateStan()
        isoMsg[12] = transTime
        isoMsg[13] = transDate
        isoMsg[41] = terminalId

        map.forEach { entry ->
            isoMsg[entry.key] = entry.value
        }
        if (calculateHash.first) {
            isoMsg[calculateHash.second] = ISOUtil.hex2byte("0000000000000000000000000000000000000000000000000000000000000000")
            isoMsg.recalcBitMap()
            val prepack = isoMsg.pack()
            isoMsg[calculateHash.second] = performSHA256Hash(ISOUtil.trim(prepack, prepack.size - 64), ISOUtil.hex2byte(keyManager.getSessionKey()))
        }

        channel.send(isoMsg)
        val resp = channel.receive()
        channel.disconnect()
        return resp
    }
}
