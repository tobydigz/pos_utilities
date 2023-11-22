package com.tobydigz.nibss_pos_helper

enum class KeyDownloadStep {
    TMK, TSK, TPK, ParamDownload, CAPK, AID,
}

interface KeyExchangeListener {
    fun onKeyDownloadStepDone(step: KeyDownloadStep, status: String)
    fun onError(step: KeyDownloadStep, e: Exception)
}