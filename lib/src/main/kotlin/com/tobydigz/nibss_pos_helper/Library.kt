package com.tobydigz.nibss_pos_helper

import com.tobydigz.nibss_pos_helper.keyexchange.KeyExchange
import com.tobydigz.nibss_pos_helper.keyexchange.KeyManager
import com.tobydigz.nibss_pos_helper.keyexchange.SocketClient
import com.tobydigz.nibss_pos_helper.keyexchange.iso8583.Packager
import org.jpos.util.Logger
import org.jpos.util.SimpleLogListener

class Library {
    fun encodePinBlock(tmk: String, encryptedTpk: String, pan: String, pin: String): String {
        val tpk = Utils.tripleDesDecode(encryptedTpk, tmk)

        val blockOne = Utils.padStringRight("0${pin.length}${pin}", 'F', 16)
        val blockTwo = "0000${pan.substring(3, 15)}"

        return Utils.tripleDesEncode(Utils.getXorOfStrings(blockOne, blockTwo), tpk)
    }

    fun decodePinBlock(tmk: String, encryptedTpk: String, pan: String, pinBlock: String): String {
        val tpk = Utils.tripleDesDecode(encryptedTpk, tmk)

        val plainPinBlock = Utils.tripleDesDecode(pinBlock, tpk)

        val paddedPAN = "0000${pan.substring(3, 15)}"

        val pin = Utils.getXorOfStrings(paddedPAN, plainPinBlock)
        return pin.substring(2, 6)
    }

    fun performKeyExchange(terminalId: String, componentKeys: Pair<String, String>, listener: KeyExchangeListener, ip: String, port: Int, secure: Boolean, type: SocketClient.ChannelType) {
        val packager = Packager()
        val channel = SocketClient.getChannel(packager, ip, port, secure, type)

        val logger = Logger()
        logger.addListener(SimpleLogListener(System.out))
        packager.setLogger(logger, "")
        channel.setLogger(logger, "")
        val keyExchange = KeyExchange(terminalId, channel, packager, KeyManager(componentKeys.first, componentKeys.second))

        var step = KeyDownloadStep.TMK
        try {
            var result: String = keyExchange.runTMK()
            listener.onKeyDownloadStepDone(step, result)
            if (!result.endsWith("00")) {
                return
            }

            step = KeyDownloadStep.TSK
            result = keyExchange.runTSK()
            listener.onKeyDownloadStepDone(KeyDownloadStep.TSK, result)
            if (!result.endsWith("00")) {
                return
            }


            step = KeyDownloadStep.TPK
            result = keyExchange.runTPK()
            listener.onKeyDownloadStepDone(step, result)
            if (!result.endsWith("00")) {
                return
            }

            step = KeyDownloadStep.ParamDownload
            result = keyExchange.runParamDownload()
            listener.onKeyDownloadStepDone(step, result)
            if (!result.endsWith("00")) {
                return
            }

            step = KeyDownloadStep.CAPK
            result = keyExchange.runCAPKDownload()
            listener.onKeyDownloadStepDone(step, result)
            if (!result.endsWith("00")) {
                return
            }

            step = KeyDownloadStep.AID
            result = keyExchange.runAIDDownload()
            listener.onKeyDownloadStepDone(KeyDownloadStep.AID, result)
            if (!result.endsWith("00")) {
                return
            }


        } catch (e: Exception) {
            listener.onError(step, e)
        }
    }
}
