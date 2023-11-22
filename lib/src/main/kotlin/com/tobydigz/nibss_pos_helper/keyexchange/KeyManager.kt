package com.tobydigz.nibss_pos_helper.keyexchange

import com.tobydigz.nibss_pos_helper.Utils

class KeyManager(private val componentKeyOne: String, private val componentKeyTwo: String) {
    private lateinit var masterKey: String
    private lateinit var sessionKey: String

    fun setEncryptedMasterKey(encryptedMasterKey: String) {
        val data = encryptedMasterKey.substring(0, 32)
        val key = Utils.getXorOfStrings(componentKeyOne, componentKeyTwo)
        masterKey = Utils.tripleDesDecode(data, key)
    }

    private fun getMasterKey(): String {
        if (this::masterKey.isInitialized) {
            return masterKey
        }

        throw Error("Master Key not set")
    }

    fun setEncryptedSessionKey(encryptedSessionKey: String) {
        val data = encryptedSessionKey.substring(0, 32)
        val key = getMasterKey()
        sessionKey = Utils.tripleDesDecode(data, key)
    }

    fun getSessionKey(): String {
        if (this::sessionKey.isInitialized) {
            return sessionKey
        }

        throw Error("Session Key not set")
    }
}