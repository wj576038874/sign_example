package com.example.sign

import android.content.Context

/**
 * author: wenjie
 * date: 2022-04-20 16:34
 * descption:
 */
object GmSSL {


    /**
     * jni调用 校验方法 对应c++函数签名为Java_com_example_sign_JniUtils_verification
     * 返回校验结果 如果返回1代表校验通过 其他值都校验失败
     */
    external fun verification(context: Context): Int

    /**
     * jni调用 其他方法 对应c++函数签名为Java_com_example_sign_JniUtils_stringFromJNI
     * 如果签名通过此函数可以正常调用返回
     */
    external fun stringFromJNI(): String

    /**
     * aes加密
     */
    external fun aesEnc(input: ByteArray, length: Int, key: ByteArray): ByteArray?

    /**
     * aes解密
     */
    external fun aesDec(input: ByteArray, length: Int, key: ByteArray): ByteArray?

    /**
     * sm4加密
     */
    external fun sm4Enc(input: ByteArray, length: Int, key: ByteArray): ByteArray?

    /**
     * sm4解密 返回数据可能为null，如果签名校验失败了 就返回null
     */
    external fun sm4Dec(input: ByteArray, length: Int, key: ByteArray): ByteArray?

    external fun sm2Enc(
        input: ByteArray,
        length: Int,
        keyA: ByteArray,
        keyB: ByteArray
    ): ByteArray?

    external fun sm2Dec(input: ByteArray, length: Int, key: ByteArray): ByteArray?

    /**
     * 当此类初始化的时候，首先会调用init方法，加载so库到内存，以便verification stringFromJNI可以正常调用
     */
    init {
        System.loadLibrary("gmssl")
    }

    fun hexStringToByteArray(s: String): ByteArray {
        val len = s.length
        val data = ByteArray(len / 2)
        var i = 0
        while (i < len) {
            data[i / 2] = ((Character.digit(s[i], 16) shl 4)
                    + Character.digit(s[i + 1], 16)).toByte()
            i += 2
        }
        return data
    }
}