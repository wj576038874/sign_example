package com.example.sign

import android.annotation.SuppressLint
import android.os.Bundle
import android.util.Base64
import android.util.Log
import androidx.appcompat.app.AppCompatActivity
import com.example.sign.databinding.ActivityMainBinding

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding


    @SuppressLint("PackageManagerGetSignatures")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        //1调用c++签名校验函数，获取校验结果
        val ret = GmSSL.verification(this)

        //2签名校验之后，调用此函数。如果校验成功，则返回正常数据，否则返回异常数据提示签名不通过
        GmSSL.stringFromJNI()
        binding.sampleText.text = GmSSL.stringFromJNI()


        val key = "01020304050607080910111213141516"
        binding.btnEnc.setOnClickListener {
            val srcStr = "qwer"
            val encMsg: ByteArray? = GmSSL.sm4Enc(
                srcStr.toByteArray(),
                srcStr.toByteArray().size,
                GmSSL.hexStringToByteArray(key)
            )
            Log.e("asd" , encMsg.toString())
            val b64SM4EncMsg = Base64.encodeToString(encMsg, Base64.DEFAULT)
            binding.sampleText.text = "加密后：$b64SM4EncMsg"
            Log.e("asd" , b64SM4EncMsg)
        }


        binding.btnDec.setOnClickListener {
            val srcStr = "51WECRlksHjTck53QoSZwA==".replace("\n", "")
            //解密
            val s: ByteArray? = GmSSL.sm4Dec(
                Base64.decode(srcStr, Base64.DEFAULT),
                Base64.decode(srcStr, Base64.DEFAULT).size,
                GmSSL.hexStringToByteArray(key)
            )
            Log.e("asd" , Base64.decode(srcStr, Base64.DEFAULT).size.toString())
            binding.sampleText.text = "加密后：${String(s!!)}"
        }

        //如果需要验证so签名的正确性，需要改app/build.gradle文件中的applicationId 应用的唯一标识 包名即可

        //本地测试 读取签名的hashcode值
//        try {
//            val packageInfo: PackageInfo =
//                packageManager.getPackageInfo(packageName, PackageManager.GET_SIGNATURES)
//            val signatures: Array<Signature> = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
//                packageInfo.signingInfo.apkContentsSigners
//            } else {
//                packageInfo.signatures
//            }
//            Log.e("asd", signatures[0].hashCode().toString())
//        } catch (e: PackageManager.NameNotFoundException) {
//            e.printStackTrace()
//        }
    }
}