#include <jni.h>
#include <string>
#include <android/log.h>
#include <malloc.h>
#include "include/openssl/aes.h"
#include "include/openssl/sms4.h"
#include "include/openssl/ossl_typ.h"
#include "include/openssl/ec.h"
#include "include/openssl/bn.h"
#include "include/openssl/obj_mac.h"
#include "include/openssl/sm2.h"
#include "include/openssl/err.h"

static int app_security;

extern "C"
JNIEXPORT jint JNICALL
Java_com_example_sign_GmSSL_verification(JNIEnv *env, jobject thiz, jobject obj) {
    //1、通过jni指针调用jni反射函数，获取android的context类
    jclass ContextWrapperClass = env->FindClass("android/content/ContextWrapper");
    //2、通过jni指针反射调用获取到的context的getPackageManager方法获取getPackageManagerMethodID的函数类
    jmethodID getPackageManagerMethodID = env->GetMethodID(ContextWrapperClass, "getPackageManager",
                                                           "()Landroid/content/pm/PackageManager;");
    //3、判断是否反射是否成功获取到getPackageManager函数类以及ContextWrapperClass类
    if (getPackageManagerMethodID == NULL || obj == NULL || ContextWrapperClass == NULL) {
        //3-1不成功 返回-1失败
        return -1;
    }

    //3-2成功执行到这里
    //4、拿到的getPackageManager函数类通过jni反射调用CallObjectMethod函数，获取getPackageManager对象
    jobject packageManagerObject = env->CallObjectMethod(obj, getPackageManagerMethodID);
    //5、判断是否反射获取到getPackageManager对象
    if (packageManagerObject == NULL) {
        //5-1没有获取到返回-2失败
        return -2;
    }

    //5-2已经获取到返回继续执行
    //6、jni反射调用context对象的getPackageName函数类
    jmethodID getPackageNameMethodID = env->GetMethodID(ContextWrapperClass, "getPackageName",
                                                        "()Ljava/lang/String;");
    //7、判断是否成功获取包名的函数
    if (getPackageNameMethodID == NULL) {
        //7-1没有获取到返回失败
        return -3;
    }
    //7-2获取成功继续执行
    //8、jni通过getPackageNameMethodID函数类，反射调用Context的PackageName函数类获取android应用的包名
    jstring packageName = (jstring) env->CallObjectMethod(obj, getPackageNameMethodID);
    //9、获取包名
    const char *tmp = env->GetStringUTFChars(packageName, NULL);
    //10、转换成字符串
    std::string packageName_ = tmp;
    //11、调用字符串find函数，确认当前获取到的包名是否包含com.example.sign
    int findPackage = packageName_.find("com.example.sign");
    //12、判断find的函数返回值，如果找到那么返回0代表合法应用，否则<0代表不合法应用
    if (findPackage < 0) {
        //12-1不合法返回失败
        return -4;
    }
    //12-2包名合法继续执行
    //13、jni反射调用GetObjectClass获取context的类
    ContextWrapperClass = env->GetObjectClass(packageManagerObject);
    //14、jni反射调用GetMethodID函数获取ContextWrapperClass的PackageInfo函数类
    jmethodID getPackageInfoMethodID = env->GetMethodID(ContextWrapperClass, "getPackageInfo",
                                                        "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");
    //15、jni通过getPackageInfoMethodID函数类反射调用PackageInfo方法，拿到packageInfo对象
    jobject packageInfo = env->CallObjectMethod(packageManagerObject, getPackageInfoMethodID,
                                                packageName, 0x40); //GET_SIGNATURES = 64;
    ContextWrapperClass = env->GetObjectClass(packageInfo);
    //16、jni反射读取packageInfo对象的signatures属性类
    jfieldID fid = env->GetFieldID(ContextWrapperClass, "signatures",
                                   "[Landroid/content/pm/Signature;");
    //17、获取signatures集合
    jobjectArray signatures = (jobjectArray) env->GetObjectField(packageInfo, fid);
    //18、拿到signatures集合中的第一个signature对象
    jobject sig = env->GetObjectArrayElement(signatures, 0);
    ContextWrapperClass = env->GetObjectClass(sig);
    //19、获取hashCode函数
    getPackageInfoMethodID = env->GetMethodID(ContextWrapperClass, "hashCode", "()I");
    //19、调用signature对象的hashCode返回int值
    int sig_value = (int) env->CallIntMethod(sig, getPackageInfoMethodID);
    //判断apk签名的hashCode值是否是指定应用的签名的hashCode值
    if (sig_value == 440920226) {
        //如果相等，说明合法应用返回1
        app_security = 1;
    } else {
        //否则验证失败，应用不合法
        app_security = -1;
    }
    return app_security;
}

extern "C"
JNIEXPORT jstring JNICALL
Java_com_example_sign_GmSSL_stringFromJNI(JNIEnv *env, jobject thiz) {
    //java调用此函数的时候，需要判断是否已经通过签名校验
    if (app_security == 1) {
        //通过
        std::string hello = "签名校验通过，成功调用so库中的方法返回数据：Hello from C++";
        return env->NewStringUTF(hello.c_str());
    }
    //不通过
    std::string hello = "签名校验不通过，so库中的方法无法调用";
    return env->NewStringUTF(hello.c_str());
}

EC_KEY *setSm2PrivateKey(char *privatekey) {
    EC_KEY *ec_key = EC_KEY_new();
    ec_key = EC_KEY_new_by_curve_name(NID_sm2p256v1);
    BIGNUM *x = BN_new();
    int iret = BN_hex2bn(&x, privatekey);
    iret = EC_KEY_set_private_key(ec_key, x);
    BN_free(x);
    return ec_key;
}

EC_KEY *setSm2PublicKey(char *keyA, char *keyB) {
    EC_KEY *ec_key = EC_KEY_new();
    ec_key = EC_KEY_new_by_curve_name(NID_sm2p256v1);

    BIGNUM *x = BN_new();
    int iret = BN_hex2bn(&x, keyA);
    BIGNUM *y = BN_new();
    iret = BN_hex2bn(&y, keyB);
    iret = EC_KEY_set_public_key_affine_coordinates(ec_key, x, y);
    //__android_log_print(ANDROID_LOG_INFO, LOG_TAG, "setSm2PublicKey:%d", iret);

    BN_free(x);
    BN_free(y);
    return ec_key;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_example_sign_GmSSL_aesEnc(JNIEnv *env, jobject instance, jbyteArray in_, jint length,
                                   jbyteArray key_) {

    if (app_security != 1) {
        //不通过
        return NULL;
    }

    jbyte *in = env->GetByteArrayElements(in_, NULL);
    jbyte *key = env->GetByteArrayElements(key_, NULL);

    int pading = AES_BLOCK_SIZE - length % AES_BLOCK_SIZE;
    int block = length / AES_BLOCK_SIZE;
    int endLen = AES_BLOCK_SIZE - pading;

    unsigned char *p = (unsigned char *) malloc(AES_BLOCK_SIZE + 1);
    memset(p, 0, AES_BLOCK_SIZE + 1);
    memset(p + endLen, pading, (size_t) pading);
    memcpy(p, in + block * AES_BLOCK_SIZE, (size_t) endLen);

    AES_KEY aes_key;
    AES_set_encrypt_key((const unsigned char *) key, 16 * 8, &aes_key);

    unsigned char *out = (unsigned char *) malloc((size_t) (length + pading + 1));
    memset(out, 0, (size_t) (length + pading + 1));

    for (int i = 0; i < block; i++) {
        AES_encrypt((const unsigned char *) (in + (i * AES_BLOCK_SIZE)),
                    out + i * AES_BLOCK_SIZE,
                    &aes_key);
    }
    AES_encrypt(p, out + block * AES_BLOCK_SIZE, &aes_key);

    jbyteArray array = env->NewByteArray(length + pading);
    env->SetByteArrayRegion(array, 0, length + pading, (const jbyte *) out);

    free(p);
    free(out);

    env->ReleaseByteArrayElements(in_, in, 0);
    env->ReleaseByteArrayElements(key_, key, 0);

    return array;
}
extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_example_sign_GmSSL_aesDec(JNIEnv *env, jobject instance, jbyteArray in_, jint length,
                                   jbyteArray key_) {

    if (app_security != 1) {
        return NULL;
    }

    jbyte *in = env->GetByteArrayElements(in_, NULL);
    jbyte *key = env->GetByteArrayElements(key_, NULL);

    AES_KEY aes_key;
    AES_set_decrypt_key((const unsigned char *) key, 16 * 8, &aes_key);

    unsigned char *out = (unsigned char *) malloc(length);
    memset(out, 0, length);

    for (int i = 0; i < length / 16; i++) {
        AES_decrypt((const unsigned char *) (in + (i * AES_BLOCK_SIZE)),
                    out + i * AES_BLOCK_SIZE,
                    &aes_key);
    }
    //去补位
    int padinglen = out[length - 1];
    memset(out + length - padinglen, 0, padinglen);

    jbyteArray array = env->NewByteArray(length - padinglen);
    env->SetByteArrayRegion(array, 0, length - padinglen, (const jbyte *) out);

    free(out);
    env->ReleaseByteArrayElements(in_, in, 0);
    env->ReleaseByteArrayElements(key_, key, 0);

    return array;
}
extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_example_sign_GmSSL_sm4Enc(JNIEnv *env, jobject instance, jbyteArray in_, jint length,
                                   jbyteArray key_) {

    if (app_security != 1) {
        //不通过
        return NULL;
    }

    jbyte *in = env->GetByteArrayElements(in_, NULL);
    jbyte *key = env->GetByteArrayElements(key_, NULL);

    int pading = SMS4_KEY_LENGTH - length % SMS4_KEY_LENGTH;
    int block = length / SMS4_KEY_LENGTH;
    int endLen = SMS4_KEY_LENGTH - pading;

    unsigned char *p = (unsigned char *) malloc(SMS4_KEY_LENGTH + 1);
    memset(p, 0, SMS4_KEY_LENGTH + 1);
    memset(p + endLen, pading, (size_t) pading);
    memcpy(p, in + block * SMS4_KEY_LENGTH, (size_t) endLen);

    sms4_key_t sms4EncKey;
    sms4_set_encrypt_key(&sms4EncKey, (const unsigned char *) key);

    unsigned char *out = (unsigned char *) malloc((size_t) (length + pading + 1));
    memset(out, 0, (size_t) (length + pading + 1));

    for (int i = 0; i < block; i++) {
        sms4_encrypt((const unsigned char *) (in + (i * 16)), out + i * 16, &sms4EncKey);
    }
    sms4_encrypt(p, out + block * 16, &sms4EncKey);

    jbyteArray array = env->NewByteArray(length + pading);
    env->SetByteArrayRegion(array, 0, length + pading, (const jbyte *) out);

    free(p);
    free(out);
    env->ReleaseByteArrayElements(in_, in, 0);
    env->ReleaseByteArrayElements(key_, key, 0);

    return array;
}
extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_example_sign_GmSSL_sm4Dec(JNIEnv *env, jobject instance, jbyteArray in_, jint length,
                                   jbyteArray key_) {

    if (app_security != 1) {
        return NULL;
    }

    jbyte *in = env->GetByteArrayElements(in_, NULL);
    jbyte *key = env->GetByteArrayElements(key_, NULL);

    sms4_key_t sms4DecKey;
    sms4_set_decrypt_key(&sms4DecKey, (const unsigned char *) key);

    unsigned char *out = (unsigned char *) malloc(length);
    memset(out, 0, length);

    for (int i = 0; i < length / 16; i++) {
        sms4_decrypt((const unsigned char *) (in + (i * 16)), out + i * 16, &sms4DecKey);
    }
    //去补位
    int padinglen = out[length - 1];
    memset(out + length - padinglen, 0, padinglen);

    jbyteArray array = env->NewByteArray(length - padinglen);
    env->SetByteArrayRegion(array, 0, length - padinglen, (const jbyte *) out);

    free(out);
    env->ReleaseByteArrayElements(in_, in, 0);
    env->ReleaseByteArrayElements(key_, key, 0);

    return array;
}
extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_example_sign_GmSSL_sm2Enc(JNIEnv *env, jobject instance, jbyteArray in_, jint length,
                                   jbyteArray keya_, jbyteArray keyb_) {

    if (app_security != 1) {
        return NULL;
    }

    jbyte *in = env->GetByteArrayElements(in_, NULL);
    jbyte *keya = env->GetByteArrayElements(keya_, NULL);
    int len_keyA = env->GetArrayLength(keya_);

    jbyte *keyb = env->GetByteArrayElements(keyb_, NULL);
    int len_keyB = env->GetArrayLength(keyb_);


    char *ykeyA = new char[len_keyA + 1];
    memset(ykeyA, NULL, len_keyA + 1);
    memcpy(ykeyA, keya, len_keyA);

    char *ykeyB = new char[len_keyB + 1];
    memset(ykeyB, NULL, len_keyB + 1);
    memcpy(ykeyB, keyb, len_keyB);


    int iRet = 0;
    EC_KEY *ec_key = setSm2PublicKey((char *) ykeyA, (char *) ykeyB);
    size_t sm2EncLen = length + 200;


    unsigned char *sm2EncMsg = (unsigned char *) malloc(sm2EncLen);
    memset(sm2EncMsg, 0, sm2EncLen);
    iRet = SM2_encrypt_with_recommended((const unsigned char *) in,
                                        (size_t) length,
                                        sm2EncMsg,
                                        &sm2EncLen,
                                        ec_key);
    //__android_log_print(ANDROID_LOG_INFO, LOG_TAG, "Java_com_aisi_crypto_Crypto_sm2Enc %d", iRet);
    if (1 != iRet) {
        ERR_load_ERR_strings();
        ERR_load_crypto_strings();

        unsigned long ulErr = ERR_get_error(); // 获取错误号
        //__android_log_print(ANDROID_LOG_INFO, LOG_TAG, "Java_com_aisi_crypto_Crypto_sm2Enc %d", iRet);
        const char *pTmp = ERR_reason_error_string(ulErr);
        puts(pTmp);
    }

    jbyteArray array = env->NewByteArray(sm2EncLen);
    env->SetByteArrayRegion(array, 0, sm2EncLen, (const jbyte *) sm2EncMsg);

    free(sm2EncMsg);
    EC_KEY_free(ec_key);

    delete ykeyA;
    delete ykeyB;

    env->ReleaseByteArrayElements(in_, in, 0);
    env->ReleaseByteArrayElements(keya_, keya, 0);
    env->ReleaseByteArrayElements(keyb_, keyb, 0);

    return array;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_example_sign_GmSSL_sm2Dec(JNIEnv *env, jobject instance, jbyteArray in_, jint length,
                                   jbyteArray key_) {

    if (app_security != 1) {
        return NULL;
    }

    jbyte *in = env->GetByteArrayElements(in_, NULL);
    jbyte *key = env->GetByteArrayElements(key_, NULL);

    int iRet = 0;
    EC_KEY *ec_key = setSm2PrivateKey((char *) key);
    size_t sm2DecLen = 0;

    iRet = SM2_decrypt(NID_sm3,
                       (const unsigned char *) in,
                       (size_t) length,
                       NULL,
                       &sm2DecLen,
                       ec_key);

    unsigned char *sm2DecMsg = (unsigned char *) malloc(sm2DecLen + 1);
    memset(sm2DecMsg, 0, sm2DecLen);

    iRet = SM2_decrypt(NID_sm3,
                       (const unsigned char *) in,
                       (size_t) length,
                       sm2DecMsg,
                       &sm2DecLen,
                       ec_key);

    jbyteArray array = env->NewByteArray(sm2DecLen);
    env->SetByteArrayRegion(array, 0, sm2DecLen, (const jbyte *) sm2DecMsg);

    free(sm2DecMsg);
    EC_KEY_free(ec_key);
    env->ReleaseByteArrayElements(in_, in, 0);
    env->ReleaseByteArrayElements(key_, key, 0);

    return array;
}