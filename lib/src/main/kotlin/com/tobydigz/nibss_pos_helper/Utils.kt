package com.tobydigz.nibss_pos_helper

import com.tobydigz.nibss_pos_helper.keyexchange.iso8583.TripleDesCipher
import org.jpos.iso.ISOException
import org.jpos.iso.ISOUtil
import java.security.InvalidKeyException
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException
import java.security.NoSuchProviderException
import java.util.*
import javax.crypto.BadPaddingException
import javax.crypto.IllegalBlockSizeException
import javax.crypto.NoSuchPaddingException

object Utils {
    @Throws(ISOException::class)
    fun generateStan(): String {
        return ISOUtil.zeropad(Random().nextInt(999999).toString(), 6)
    }

    private fun fromHex(c: Char): Int {
        if (c >= '0' && c <= '9') {
            return c.code - '0'.code
        }
        if (c >= 'A' && c <= 'F') {
            return c.code - 'A'.code + 10
        }
        if (c >= 'a' && c <= 'f') {
            return c.code - 'a'.code + 10
        }
        throw IllegalArgumentException()
    }

    private fun toHex(nybble: Int): Char {
        require(!(nybble < 0 || nybble > 15))
        return "0123456789ABCDEF"[nybble]
    }

    fun getXorOfStrings(stringOne: String, stringTwo: String): String {
        val chars = CharArray(stringOne.length)
        for (i in chars.indices) {
            chars[i] = toHex(fromHex(stringOne[i]) xor fromHex(stringTwo[i]))
        }
        return String(chars)
    }

    @Throws(NoSuchPaddingException::class, NoSuchAlgorithmException::class, InvalidKeyException::class, NoSuchProviderException::class, BadPaddingException::class, IllegalBlockSizeException::class)
    fun tripleDesDecode(data: String, key: String): String {
        val keyBytes = ISOUtil.hex2byte(key)
        val dataBytes = ISOUtil.hex2byte(data)
        val cipher4KeyDecryption = TripleDesCipher(keyBytes)
        val plainKey = cipher4KeyDecryption.decode(dataBytes)
        return ISOUtil.hexString(plainKey)
    }

    @Throws(NoSuchPaddingException::class, NoSuchAlgorithmException::class, InvalidKeyException::class, NoSuchProviderException::class, BadPaddingException::class, IllegalBlockSizeException::class)
    fun tripleDesEncode(data: String?, key: String?): String {
        val keyBytes = ISOUtil.hex2byte(key)
        val dataBytes = ISOUtil.hex2byte(data)
        val cipher4KeyDecryption = TripleDesCipher(keyBytes)
        val encryptedKey = cipher4KeyDecryption.encode(dataBytes)
        return ISOUtil.hexString(encryptedKey)
    }

    @Throws(ISOException::class)
    fun padStringRight(input: String?, pad: Char, length: Int): String {
        return ISOUtil.padright(input, length, pad)
    }

    @Throws(NoSuchAlgorithmException::class)
    fun performSHA256Hash(input: ByteArray?, seed: ByteArray?): ByteArray {
        val md = MessageDigest.getInstance("SHA-256")
        md.reset()
        md.update(seed)
        md.update(input)
        return md.digest()
    }
}
