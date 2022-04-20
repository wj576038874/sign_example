//package com.example.sign
//
//import android.content.Context
//
///**
// * author: wenjie
// * date: 2022-04-13 09:57
// * descption:
// */
//object JniUtils {
//
//    /**
//     * jni调用 校验方法 对应c++函数签名为Java_com_example_sign_JniUtils_verification
//     * 返回校验结果 如果返回1代表校验通过 其他值都校验失败
//     */
//    external fun verification(context: Context): Int
//
//    /**
//     * jni调用 其他方法 对应c++函数签名为Java_com_example_sign_JniUtils_stringFromJNI
//     * 如果签名通过此函数可以正常调用返回
//     */
//    external fun stringFromJNI(): String
//
//
//    /**
//     * 当此类初始化的时候，首先会调用init方法，加载so库到内存，以便verification stringFromJNI可以正常调用
//     */
//    init {
//        System.loadLibrary("sign")
//    }
//}